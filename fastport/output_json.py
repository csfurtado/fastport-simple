import json
from pathlib import Path
from datetime import datetime
from typing import Any, Dict, Optional

BASE_DIR = Path(__file__).resolve().parents[1]
REPORTS_DIR = BASE_DIR / "reports"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

def _timestamped_name(base: str, ext: str) -> str:
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    return f"{base}-{ts}.{ext}"

def save_json(results: Dict[str, Any], duration: float, filename: Optional[str] = None) -> str:
    if not filename:
        filename = _timestamped_name("scan", "json")
    filepath = REPORTS_DIR / filename

    out = {
        "meta": {
            "timestamp": datetime.utcnow().isoformat(),
            "scanned_hosts": len(results),
            "alive_hosts": sum(1 for r in results.values() if r.get("ports")),
            "duration": duration
        },
        "hosts": results,
    }

    with open(filepath, "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2, ensure_ascii=False)

    return str(filepath.resolve())
