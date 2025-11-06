"""
Async scanner engine (discovery -> scan -> probe) with tunable timeouts and concurrency.
- discovery_hosts(...) -> quick probe on small set of ports to detect live hosts
- scan_open_ports_then_probe(...) -> scan ports on live hosts and enrich open ports with fingerprinting
- discover_and_scan(...) -> convenience wrapper
"""

import asyncio
import socket
from typing import Any, Dict, Iterable, List, Union
from .utils import ip_range_from_cidr, parse_ports
from .probes import full_port_probe  # novo probes.py

# optional progress bar
try:
    from tqdm import tqdm
except Exception:
    tqdm = None

# ---------------- low-level probes ----------------

async def _tcp_connect(host: str, port: int, timeout: float) -> Dict[str, Any]:
    """Try TCP connect + small banner read. Returns dict with state/banner."""
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
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        pass
    return res


async def _udp_probe(host: str, port: int, timeout: float) -> Dict[str, Any]:
    """Best-effort UDP probe."""
    res = {"port": port, "protocol": "udp", "state": "closed", "service": None, "banner": None}

    def _send_recv():
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(timeout)
                try:
                    s.sendto(b"\x00", (host, port))
                except Exception:
                    return None, "senderr"
                try:
                    data, _ = s.recvfrom(4096)
                    return data, None
                except socket.timeout:
                    return None, "timeout"
                except Exception:
                    return None, "err"
        except Exception:
            return None, "sockerr"

    loop = asyncio.get_running_loop()
    data, err = await loop.run_in_executor(None, _send_recv)
    if data:
        res["state"] = "open"
        try:
            res["banner"] = data.decode("utf-8", errors="replace").strip()
        except Exception:
            res["banner"] = repr(data)
    else:
        res["state"] = "open|filtered" if err == "timeout" else "closed"
    return res


async def probe_port(host: str, port: int, protocol: str = "tcp", timeout: float = 0.8) -> Dict[str, Any]:
    """Dispatch to protocol-specific probe."""
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
    """Quick discovery: probe small set of ports to detect live hosts."""
    if isinstance(targets, str):
        targets = [targets]
    expanded = expand_targets(list(targets))
    probe_ports_list = parse_ports(str(probe_ports)) if not isinstance(probe_ports, (list, tuple)) else list(probe_ports)
    protocols = [p.lower() for p in protocols] if isinstance(protocols, (list, tuple)) else [str(protocols).lower()]

    results: Dict[str, Any] = {}
    sem = asyncio.Semaphore(concurrency)

    async def guarded_probe(h: str, p: int, proto: str):
        async with sem:
            return await probe_port(h, p, proto, timeout=timeout)

    use_tqdm = tqdm is not None
    progress = tqdm(total=len(expanded), desc="Discovery (hosts)", unit="host", dynamic_ncols=True) if use_tqdm else None

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
    """Scan ports and enrich open ports with full fingerprinting."""
    if isinstance(hosts_or_discovery, dict):
        host_list = [h for h, v in hosts_or_discovery.items() if v.get("alive")]
    elif isinstance(hosts_or_discovery, list):
        host_list = hosts_or_discovery
    elif isinstance(hosts_or_discovery, str):
        host_list = expand_targets([hosts_or_discovery])
    else:
        raise ValueError("hosts_or_discovery must be list, dict or str")

    if not host_list:
        return {}

    ports_list = list(ports_spec) if isinstance(ports_spec, (list, tuple)) else parse_ports(str(ports_spec))
    protocols = [p.lower() for p in protocols] if isinstance(protocols, (list, tuple)) else [str(protocols).lower()]

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
