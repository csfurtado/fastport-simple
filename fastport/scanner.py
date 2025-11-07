"""
Async scanner engine (discovery -> scan -> probe) with tunable timeouts and concurrency.
- discovery_hosts(...) -> quick probe on small set of ports to detect live hosts
- scan_open_ports_then_probe(...) -> scan ports on live hosts and enrich open ports with fingerprinting
- discover_and_scan(...) -> convenience wrapper
"""

import asyncio
import socket
import re
from typing import Any, Dict, Iterable, List, Union, Tuple
from .utils import ip_range_from_cidr, parse_ports
from .probes import full_port_probe  # novo probes.py

# optional progress bar
try:
    from tqdm import tqdm
except Exception:
    tqdm = None


# ---------------- Service / Version inference helper ----------------

_COMMON_PORT_SERVICE = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    143: "imap",
    443: "https",
    3306: "mysql",
    3389: "rdp",
    8080: "http-proxy",
    5900: "vnc",
    139: "smb",
    445: "smb",
}


_BANNER_REGEXPS = [
    ("apache", re.compile(r"apache(?:/|\s)?([0-9]+\.[0-9]+(?:\.[0-9]+)?)?", re.I)),
    ("nginx", re.compile(r"nginx(?:/|\s)?([0-9]+\.[0-9]+(?:\.[0-9]+)?)?", re.I)),
    ("openssh", re.compile(r"OpenSSH[_\- ]?([0-9]+\.[0-9]+(?:p[0-9]+)?)", re.I)),
    ("vsftpd", re.compile(r"vsFTPd(?:/|\s)?([0-9]+\.[0-9]+)?", re.I)),
    ("postfix", re.compile(r"Postfix", re.I)),
    ("iis", re.compile(r"microsoft-iis(?:/|\s)?([0-9]+\.[0-9]+)?", re.I)),
    ("samba", re.compile(r"samba(?:/|\s)?([0-9]+\.[0-9]+)?", re.I)),
]


def _safe_banner_text(banner: Any) -> str:
    """Safely decode banner (bytes, str, None)."""
    if not banner:
        return ""
    if isinstance(banner, bytes):
        try:
            return banner.decode("utf-8", errors="replace")
        except Exception:
            return repr(banner)
    return str(banner)


def infer_service_version(port_entry: Dict[str, Any]) -> Tuple[Union[str, None], Union[str, None]]:
    """Try to infer service/version from banner, HTTP/SSH info or port number."""
    banner = _safe_banner_text(port_entry.get("banner"))
    port = port_entry.get("port")
    proto = port_entry.get("protocol", "tcp")

    # --- explicit metadata ---
    if port_entry.get("http"):
        headers = port_entry["http"].get("headers", {})
        srv = headers.get("Server") or headers.get("server")
        if srv:
            m = re.match(r"([\w\-\_]+)(?:/([\d\.]+))?", srv)
            if m:
                return m.group(1).lower(), m.group(2)

    if port_entry.get("ssh"):
        ident = _safe_banner_text(port_entry["ssh"].get("ssh_ident") or banner)
        m = re.search(r"OpenSSH[_\- ]?([0-9]+\.[0-9]+)", ident, re.I)
        if m:
            return "openssh", m.group(1)
        return "ssh", None

    # --- banner regexes ---
    for hint, rx in _BANNER_REGEXPS:
        m = rx.search(banner)
        if m:
            return hint, m.group(1) if m.groups() else None

    # --- fallback by port ---
    if port in _COMMON_PORT_SERVICE:
        return _COMMON_PORT_SERVICE[port], None

    try:
        return socket.getservbyport(port, proto), None
    except Exception:
        return None, None


# ---------------- low-level probes ----------------

async def _tcp_connect(host: str, port: int, timeout: float) -> Dict[str, Any]:
    res = {"port": port, "protocol": "tcp", "state": "closed", "service": None, "banner": None}
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        res["state"] = "open"
        try:
            writer.write(b"\r\n")
            await writer.drain()
        except Exception:
            pass
        try:
            data = await asyncio.wait_for(reader.read(1024), timeout=min(0.35, timeout / 2))
            if data:
                res["banner"] = data.decode("utf-8", errors="replace").strip()
        except asyncio.TimeoutError:
            pass
        writer.close()
        await writer.wait_closed()
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        pass
    return res


async def _udp_probe(host: str, port: int, timeout: float) -> Dict[str, Any]:
    res = {"port": port, "protocol": "udp", "state": "closed", "service": None, "banner": None}

    def _send_recv():
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(timeout)
                s.sendto(b"\x00", (host, port))
                data, _ = s.recvfrom(4096)
                return data
        except socket.timeout:
            return None
        except Exception:
            return None

    loop = asyncio.get_running_loop()
    data = await loop.run_in_executor(None, _send_recv)
    if data:
        res["state"] = "open"
        res["banner"] = data.decode("utf-8", errors="replace").strip()
    else:
        res["state"] = "open|filtered"
    return res


async def probe_port(host: str, port: int, protocol: str = "tcp", timeout: float = 0.8) -> Dict[str, Any]:
    proto = protocol.lower()
    if proto == "tcp":
        return await _tcp_connect(host, port, timeout)
    elif proto == "udp":
        return await _udp_probe(host, port, timeout)
    else:
        raise ValueError(f"Unsupported protocol: {protocol}")


# ---------------- discovery ----------------

async def discover_hosts(
    targets: Union[str, Iterable[str]],
    probe_ports: Union[str, Iterable[int]] = "22,80,443",
    concurrency: int = 500,
    timeout: float = 0.6,
    protocols: Iterable[str] = ("tcp",),
    batch_hosts: int = 200,
) -> Dict[str, Any]:
    if isinstance(targets, str):
        targets = [targets]
    expanded = ip_range_from_cidr(list(targets))
    probe_ports_list = parse_ports(str(probe_ports)) if not isinstance(probe_ports, (list, tuple)) else list(probe_ports)
    protocols = [p.lower() for p in protocols]

    results: Dict[str, Any] = {}
    sem = asyncio.Semaphore(concurrency)
    use_tqdm = tqdm is not None
    progress = tqdm(total=len(expanded), desc="Discovery (hosts)", unit="host", dynamic_ncols=True) if use_tqdm else None

    async def guarded_probe(h: str, p: int, proto: str):
        async with sem:
            return await probe_port(h, p, proto, timeout=timeout)

    for i in range(0, len(expanded), batch_hosts):
        batch = expanded[i:i + batch_hosts]

        async def scan_host(h: str):
            tasks = [asyncio.create_task(guarded_probe(h, p, proto)) for proto in protocols for p in probe_ports_list]
            probe_results = await asyncio.gather(*tasks)
            open_count = sum(1 for r in probe_results if r.get("state") in ("open", "open|filtered"))
            results[h] = {"host": h, "alive": open_count > 0, "open_count": open_count, "probes": probe_results}
            if progress:
                progress.update(1)

        await asyncio.gather(*[scan_host(h) for h in batch])

    if progress:
        progress.close()
    return results


# ---------------- full scan + enriched probe ----------------

async def scan_open_ports_then_probe(
    hosts_or_discovery: Union[List[str], Dict[str, Any], str],
    ports_spec: Union[str, Iterable[int]] = "1-1024",
    protocols: Iterable[str] = ("tcp",),
    concurrency: int = 1000,
    timeout: float = 0.8,
    batch_hosts: int = 20,
) -> Dict[str, Any]:
    if isinstance(hosts_or_discovery, dict):
        host_list = [h for h, v in hosts_or_discovery.items() if v.get("alive")]
    elif isinstance(hosts_or_discovery, list):
        host_list = hosts_or_discovery
    elif isinstance(hosts_or_discovery, str):
        host_list = ip_range_from_cidr([hosts_or_discovery])
    else:
        raise ValueError("hosts_or_discovery must be list, dict or str")

    if not host_list:
        return {}

    ports_list = list(ports_spec) if isinstance(ports_spec, (list, tuple)) else parse_ports(str(ports_spec))
    protocols = [p.lower() for p in protocols]
    results: Dict[str, Any] = {}

    sem = asyncio.Semaphore(concurrency)
    use_tqdm = tqdm is not None
    progress_hosts = tqdm(total=len(host_list), desc="Hosts scanned", unit="host", dynamic_ncols=True) if use_tqdm else None

    for i in range(0, len(host_list), batch_hosts):
        batch = host_list[i:i + batch_hosts]

        async def process_host(h: str):
            async def guarded(h, p, proto):
                async with sem:
                    base_res = await probe_port(h, p, proto, timeout=timeout)
                    if base_res.get("state") in ("open", "open|filtered"):
                        banner_bytes = base_res.get("banner").encode() if base_res.get("banner") else None
                        full_res = await full_port_probe(h, p, banner=banner_bytes)
                        base_res.update(full_res)

                        # 🔍 infer service + version
                        svc, ver = infer_service_version(base_res)
                        if svc and not base_res.get("service"):
                            base_res["service"] = svc
                        if ver and not base_res.get("version"):
                            base_res["version"] = ver

                    return base_res

            tasks = [asyncio.create_task(guarded(h, p, proto)) for proto in protocols for p in ports_list]
            opens: List[Dict[str, Any]] = []

            for fut in asyncio.as_completed(tasks):
                r = await fut
                if r.get("state") in ("open", "open|filtered"):
                    opens.append(r)

            results[h] = {"host": h, "ports": opens, "open_count": len(opens)}
            if progress_hosts:
                progress_hosts.update(1)

        await asyncio.gather(*[process_host(h) for h in batch])

    if progress_hosts:
        progress_hosts.close()

    return results


# ---------------- convenience wrapper ----------------

async def discover_and_scan(
    targets: Union[str, Iterable[str]],
    probe_ports: Union[str, Iterable[int]] = "22,80,443",
    ports_spec: Union[str, Iterable[int]] = "1-1024",
    protocols: Iterable[str] = ("tcp", "udp"),
    concurrency: int = 1000,
    timeout: float = 0.8,
    discovery_batch: int = 200,
    scan_batch: int = 20,
) -> Dict[str, Any]:
    disco = await discover_hosts(targets, probe_ports=probe_ports, protocols=protocols,
                                 concurrency=concurrency, timeout=timeout, batch_hosts=discovery_batch)
    live = [h for h, v in disco.items() if v.get("alive")]
    if not live:
        return {}
    results = await scan_open_ports_then_probe(live, ports_spec=ports_spec, protocols=protocols,
                                               concurrency=concurrency, timeout=timeout, batch_hosts=scan_batch)
    return results
