import asyncio
import subprocess
import time
import socket
import webbrowser
import ipaddress
from pathlib import Path
from datetime import datetime, timezone

from fastport.scanner import scan_open_ports_then_probe
from fastport.utils import ip_range_from_cidr
from fastport.output_json import save_json
from fastport.output_csv import save_csv
from fastport.output_pdf import save_pdf
from api.visuals import generate_visuals


def is_port_in_use(port=5000):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(("localhost", port)) == 0


def start_api_server():
    if not is_port_in_use():
        print("Starting API server...")
        api_path = Path(__file__).resolve().parent / "api" / "api.py"
        subprocess.Popen(["python", str(api_path)])
        time.sleep(1)
    else:
        print("API server is already running.")


def is_valid_cidr(cidr: str) -> bool:
    try:
        ipaddress.IPv4Network(cidr, strict=False)
        return True
    except ValueError:
        return False


async def main():
    start_api_server()

    cidr = input("Enter target IP or CIDR: ").strip()
    if not is_valid_cidr(cidr):
        print("Invalid IP or CIDR format. Try something like 192.168.1.0/24 or 10.0.2.2")
        return

    hosts = ip_range_from_cidr(cidr)
    ports = list(range(1, 1025))  # adjust to 65535 for full scan

    concurrency = 500
    timeout = 0.5

    print(f"Scanning {len(hosts)} hosts...")
    start_time = time.time()

    results = await scan_open_ports_then_probe(
        hosts,
        ports_spec=ports,
        protocols=("tcp",),
        concurrency=concurrency,
        timeout=timeout,
        batch_hosts=20
    )

    duration = time.time() - start_time

    base_dir = Path(__file__).resolve().parent
    reports_dir = base_dir / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
   

    # Save reports
    save_json(results, duration, reports_dir / "scan.json")
    save_csv(results, reports_dir / "scan.csv")
    save_pdf(results, reports_dir / "scan.pdf")


    # Generate visual assets for the frontend
    assets_dir = base_dir / "api" / "frontend" / "assets"
    assets_dir.mkdir(parents=True, exist_ok=True)
    generate_visuals(results, assets_dir)

    print(f"\nScan complete in {duration:.2f} seconds.")
    scanned = len(results)
    alive = sum(1 for r in results.values() if r.get("ports"))
    print(f"{scanned} hosts scanned, {alive} alive.")
    print("Reports saved in /reports")
    print("Report available at: http://localhost:5000")

    choice = input("Open report in browser? (y/n): ").strip().lower()
    if choice == "y":
        webbrowser.open("http://localhost:5000")


if __name__ == "__main__":
    asyncio.run(main())
