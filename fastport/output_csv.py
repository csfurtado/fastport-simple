import csv
from pathlib import Path
from datetime import datetime
from typing import Any, Dict, Optional

BASE_DIR = Path(__file__).resolve().parents[1]
REPORTS_DIR = BASE_DIR / "reports"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

def _timestamped_name(base: str, ext: str) -> str:
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    return f"{base}-{ts}.{ext}"

def _flatten_os_guess(os_guess: Any) -> str:
    if not os_guess:
        return ""
    if isinstance(os_guess, dict):
        return f"{os_guess.get('family','')};{os_guess.get('confidence','')}"
    return str(os_guess)

def save_csv(results: Dict[str, Any], filename: Optional[str] = None) -> str:
    if not filename:
        filename = _timestamped_name("scan", "csv")
    filepath = REPORTS_DIR / filename

    fieldnames = [
        "timestamp", "host", "port", "protocol", "state", "service", "version",
        "fingerprint", "os_guess", "banner_preview", "http_title", "tls_sha256",
    ]

    with open(filepath, "w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        ts = datetime.utcnow().isoformat()
        for host, data in results.items():
            ports = data.get("ports", [])
            for p in ports:
                row = {
                    "timestamp": ts,
                    "host": host,
                    "port": p.get("port"),
                    "protocol": p.get("protocol", "tcp"),
                    "state": p.get("state", ""),
                    "service": p.get("service", ""),
                    "version": p.get("version", ""),
                    "fingerprint": p.get("fingerprint", ""),
                    "os_guess": _flatten_os_guess(p.get("os_guess")),
                    "banner_preview": (p.get("ascii_preview") or p.get("banner") or "")[:200],
                    "http_title": (p.get("http") or {}).get("title", ""),
                    "tls_sha256": (p.get("tls_cert") or {}).get("sha256", ""),
                }
                writer.writerow(row)

    return str(filepath.resolve())
