import asyncio
import ssl
import socket
import base64
import hashlib
import re
from typing import Dict, Any, Optional
import aiohttp


# -----------------------------
# HTTP probe
# -----------------------------
async def probe_http(host: str, port: int, timeout: float = 5.0) -> Dict[str, Any]:
    result = {}
    for scheme in ("http", "https"):
        url = f"{scheme}://{host}:{port}"
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=timeout, ssl=(scheme == "https")) as resp:
                    text = await resp.text(errors="ignore")
                    headers = dict(resp.headers)
                    title = None
                    if "<title>" in text.lower():
                        start = text.lower().find("<title>") + 7
                        end = text.lower().find("</title>", start)
                        title = text[start:end].strip()
                    cookies = {k: v.value for k, v in session.cookie_jar.filter_cookies(url).items()}
                    result.update({
                        "protocol": scheme.upper(),
                        "status": resp.status,
                        "headers": headers,
                        "title": title,
                        "cookies": cookies,
                    })
                    break
        except Exception:
            continue
    return result


# -----------------------------
# TLS / HTTPS certificate probe
# -----------------------------
async def probe_tls_cert_async(host: str, port: int, timeout: float = 5.0) -> Dict[str, Any]:
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, probe_tls_cert_sync, host, port, timeout)


def probe_tls_cert_sync(host: str, port: int, timeout: float = 5.0) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert_bin = ssock.getpeercert(binary_form=True)
                parsed_cert = ssock.getpeercert()
                if cert_bin and parsed_cert:
                    sha256_hash = hashlib.sha256(cert_bin).hexdigest()
                    result.update({
                        "subject": dict(x[0] for x in parsed_cert.get("subject", [])),
                        "issuer": dict(x[0] for x in parsed_cert.get("issuer", [])),
                        "notBefore": parsed_cert.get("notBefore"),
                        "notAfter": parsed_cert.get("notAfter"),
                        "serialNumber": parsed_cert.get("serialNumber"),
                        "sha256": sha256_hash,
                        "self_signed": parsed_cert.get("issuer") == parsed_cert.get("subject"),
                    })
    except Exception as e:
        result["error"] = str(e)
    return result


# -----------------------------
# SSH probe
# -----------------------------
async def probe_ssh_ident(host: str, port: int = 22, timeout: float = 5.0) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        ident = await asyncio.wait_for(reader.readline(), timeout=timeout)
        ident_str = ident.decode(errors="ignore").strip()
        result["ssh_ident"] = ident_str
        writer.close()
        await writer.wait_closed()
    except Exception as e:
        result["error"] = str(e)
    return result


# -----------------------------
# MySQL version probe
# -----------------------------
async def probe_mysql_version(host: str, port: int = 3306, timeout: float = 3.0) -> Dict[str, Any]:
    out = {}
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        data = await asyncio.wait_for(reader.read(4096), timeout=timeout)
        if data:
            s = data.decode('latin-1', errors='ignore')
            m = re.search(r"([0-9]+\.[0-9]+(?:\.[0-9]+)?)", s)
            if m:
                out["mysql_version"] = m.group(1)
            out["mysql_banner_raw"] = s[:200]
        writer.close()
        await writer.wait_closed()
    except Exception as e:
        out["error"] = str(e)
    return out


# -----------------------------
# PostgreSQL version probe
# -----------------------------
async def probe_postgres_version(host: str, port: int = 5432, timeout: float = 3.0) -> Dict[str, Any]:
    out = {}
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        sslreq = (8).to_bytes(4, "big") + (80877103).to_bytes(4, "big")
        writer.write(sslreq)
        await writer.drain()
        resp = await asyncio.wait_for(reader.read(1), timeout=timeout)
        if resp:
            out["ssl_response"] = resp.decode(errors="ignore")
        try:
            more = await asyncio.wait_for(reader.read(1024), timeout=0.8)
            if more:
                s = more.decode('latin-1', errors='ignore')
                m = re.search(r"PostgreSQL(?:\s|/)?([0-9]+\.[0-9]+(?:\.[0-9]+)?)?", s, re.I)
                if m:
                    out["postgres_version"] = m.group(1)
                out["postgres_banner_raw"] = s[:200]
        except asyncio.TimeoutError:
            pass
        writer.close()
        await writer.wait_closed()
    except Exception as e:
        out["error"] = str(e)
    return out


# -----------------------------
# Raw banner decoder
# -----------------------------
def decode_raw_bytes(data: bytes, max_len: int = 400) -> Dict[str, Any]:
    if not data:
        return {"banner_raw_b64": None, "ascii_preview": None, "length": 0, "md5": None}
    b64 = base64.b64encode(data).decode()
    ascii_preview = "".join([chr(b) if 32 <= b <= 126 else "." for b in data])
    md5_hash = hashlib.md5(data).hexdigest()
    return {
        "banner_raw_b64": b64[: max_len * 2],
        "ascii_preview": ascii_preview[:max_len],
        "length": len(data),
        "md5": md5_hash,
    }


# -----------------------------
# Service inference
# -----------------------------
def infer_service(port: int, banner: Optional[str], http: Optional[Dict[str, Any]], ssh: Optional[Dict[str, Any]]) -> Dict[str, str]:
    service = None
    version = None
    banner_lower = (banner or "").lower()

    common_ports = {
        21: "ftp", 22: "ssh", 25: "smtp", 53: "dns", 80: "http",
        110: "pop3", 143: "imap", 443: "https", 3306: "mysql",
        3389: "rdp", 5432: "postgresql", 8080: "http-proxy", 8443: "https-alt"
    }
    if port in common_ports:
        service = common_ports[port]

    if ssh and "ssh_ident" in ssh:
        service = "ssh"
        parts = ssh["ssh_ident"].split("-")
        if len(parts) >= 2:
            version = parts[-1]

    if http and "headers" in http:
        hdrs = http["headers"]
        srv = hdrs.get("Server") or hdrs.get("server")
        if srv:
            m = re.match(r"([\w\-\.]+)(?:/([\d\.]+))?", srv)
            if m:
                service = m.group(1).lower()
                version = m.group(2)

    if not service and banner_lower:
        if "ssh" in banner_lower:
            service = "ssh"
        elif "smtp" in banner_lower:
            service = "smtp"
        elif "mysql" in banner_lower:
            service = "mysql"
        elif "postgres" in banner_lower:
            service = "postgresql"
        elif "ftp" in banner_lower:
            service = "ftp"
        elif "http" in banner_lower or "html" in banner_lower:
            service = "http"

    return {"service": service, "version": version}


# -----------------------------
# Unified probe function
# -----------------------------
async def full_port_probe(host: str, port: int, banner: Optional[bytes] = None) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    banner_text = None

    if banner:
        decoded = decode_raw_bytes(banner)
        result.update(decoded)
        banner_text = decoded.get("ascii_preview")

    http_res = tls_res = ssh_res = None

    if port in (80, 443, 8080, 8443):
        try:
            http_res = await probe_http(host, port)
            result["http"] = http_res
        except Exception as e:
            result["http_error"] = str(e)

    if port in (443, 8443):
        try:
            tls_res = await probe_tls_cert_async(host, port)
            result["tls_cert"] = tls_res
        except Exception as e:
            result["tls_error"] = str(e)

    if port == 22:
        try:
            ssh_res = await probe_ssh_ident(host, port)
            result["ssh"] = ssh_res
        except Exception as e:
            result["ssh_error"] = str(e)

    # Database probes
    if port == 3306:
        mysql_info = await probe_mysql_version(host, port)
        if mysql_info:
            result["mysql"] = mysql_info
            if mysql_info.get("mysql_version"):
                result["service"] = "mysql"
                result["version"] = mysql_info["mysql_version"]

    if port == 5432:
        pg_info = await probe_postgres_version(host, port)
        if pg_info:
            result["postgresql"] = pg_info
            if pg_info.get("postgres_version"):
                result["service"] = "postgresql"
                result["version"] = pg_info["postgres_version"]

    inferred = infer_service(port, banner_text, http_res, ssh_res)
    result.update({k: v for k, v in inferred.items() if v and not result.get(k)})

    fp_source = (banner_text or "") + str(result.get("service") or "")
    result["fingerprint"] = hashlib.sha1(fp_source.encode("utf-8", errors="ignore")).hexdigest()[:12]

    return result
