# fastport/probes.py
import asyncio
import ssl
import socket
import base64
import hashlib
from typing import Dict, Any, Optional
from urllib.parse import urlparse

import aiohttp

# -----------------------------
# HTTP probe
# -----------------------------
async def probe_http(host: str, port: int, timeout: float = 5.0) -> Dict[str, Any]:
    """
    Attempt to connect via HTTP/HTTPS and get headers, server info, title, cookies.
    """
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
                    break  # stop after successful probe
        except Exception:
            continue
    return result


# -----------------------------
# TLS / HTTPS certificate probe
# -----------------------------
async def probe_tls_cert_async(host: str, port: int, timeout: float = 5.0) -> Dict[str, Any]:
    """
    Fetch TLS certificate info asynchronously.
    """
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, probe_tls_cert_sync, host, port, timeout)


def probe_tls_cert_sync(host: str, port: int, timeout: float = 5.0) -> Dict[str, Any]:
    """
    Fetch TLS certificate info synchronously.
    """
    result: Dict[str, Any] = {}
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert(binary_form=True)
                if cert:
                    # SHA256 hash
                    sha256_hash = hashlib.sha256(cert).hexdigest()
                    parsed_cert = ssock.getpeercert()
                    result.update({
                        "subject": dict(x[0] for x in parsed_cert.get("subject", [])),
                        "issuer": dict(x[0] for x in parsed_cert.get("issuer", [])),
                        "notBefore": parsed_cert.get("notBefore"),
                        "notAfter": parsed_cert.get("notAfter"),
                        "serialNumber": parsed_cert.get("serialNumber"),
                        "sha256": sha256_hash,
                        "expired": parsed_cert.get("notAfter") < ssl.cert_time_to_seconds(parsed_cert.get("notAfter")) if parsed_cert.get("notAfter") else None,
                        "self_signed": parsed_cert.get("issuer") == parsed_cert.get("subject"),
                    })
    except Exception as e:
        result["error"] = str(e)
    return result


# -----------------------------
# SSH probe
# -----------------------------
async def probe_ssh_ident(host: str, port: int = 22, timeout: float = 5.0) -> Dict[str, Any]:
    """
    Fetch SSH identification string.
    """
    result: Dict[str, Any] = {}
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        ident = await asyncio.wait_for(reader.readline(), timeout=timeout)
        result["ssh_ident"] = ident.decode(errors="ignore").strip()
        writer.close()
        await writer.wait_closed()
    except Exception as e:
        result["error"] = str(e)
    return result


# -----------------------------
# Raw banner / bytes decoder
# -----------------------------
def decode_raw_bytes(data: bytes, max_len: int = 400) -> Dict[str, Any]:
    """
    Store raw banner as base64, ASCII printable parts, length and hash.
    """
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
# Unified probe function
# -----------------------------
async def full_port_probe(host: str, port: int, banner: Optional[bytes] = None) -> Dict[str, Any]:
    """
    Run all relevant probes and merge results:
    - banner decoding
    - HTTP / HTTPS
    - TLS certificate
    - SSH
    """
    result: Dict[str, Any] = {}
    if banner:
        result.update(decode_raw_bytes(banner))

    # HTTP/HTTPS
    if port in (80, 443, 8080, 8443):
        try:
            http_res = await probe_http(host, port)
            result["http"] = http_res
        except Exception as e:
            result["http_error"] = str(e)

    # TLS
    if port in (443, 8443):
        try:
            tls_res = await probe_tls_cert_async(host, port)
            result["tls_cert"] = tls_res
        except Exception as e:
            result["tls_error"] = str(e)

    # SSH
    if port == 22:
        try:
            ssh_res = await probe_ssh_ident(host, port)
            result["ssh"] = ssh_res
        except Exception as e:
            result["ssh_error"] = str(e)

    return result
