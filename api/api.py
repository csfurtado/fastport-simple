from flask import Flask, jsonify, send_from_directory
from flask_cors import CORS
from pathlib import Path
import json
from visuals import generate_visuals

app = Flask(__name__)
CORS(app)

# Paths
BASE_DIR = Path(__file__).resolve().parent
REPORTS_DIR = BASE_DIR.parent / "reports"
FRONTEND_DIR = BASE_DIR / "frontend"
ASSETS_DIR = FRONTEND_DIR / "assets"

def get_latest_json_report():
    json_files = sorted(REPORTS_DIR.glob("scan*.json"), reverse=True)
    print(f"Found JSON reports: {[f.name for f in json_files]}")
    if not json_files:
        print("No JSON reports found.")
        return None
    latest_file = json_files[0]
    print(f"📄 Loading: {latest_file.name}")
    with open(latest_file, "r", encoding="utf-8") as f:
        return json.load(f)

@app.route("/api/report")
def report():
    """Returns the latest scan results as JSON."""
    print("🔍 Endpoint /api/report was called")
    data = get_latest_json_report()
    if not data:
        print("No data loaded from JSON.")
        return jsonify({
            "title": "Scan Report",
            "summary": "No report found.",
            "meta": {},
            "results": []
        })

    meta = data.get("meta", {})
    hosts = data.get("hosts", {})
    print(f"Hosts found: {list(hosts.keys())}")

    results = []
    for host_ip, host_data in hosts.items():
        ports = host_data.get("ports", [])
        print(f"➡️ Host {host_ip} has {len(ports)} ports")

        if not isinstance(ports, list):
            print(f"Skipping host {host_ip} — ports is not a list: {ports}")
            continue

        for port in ports:
            result = {
                "host": host_ip,
                "port": port.get("port"),
                "protocol": port.get("protocol"),
                "state": port.get("state", "unknown"),
                "service": port.get("service"),
                "version": port.get("version"),
                "ascii_preview": port.get("ascii_preview"),
                "fingerprint": port.get("fingerprint"),
                "http": {
                    "title": port.get("http", {}).get("title"),
                    "headers": {
                        "Server": port.get("http", {}).get("headers", {}).get("Server")
                    }
                },
                "tls_cert": {
                    "error": port.get("tls_cert", {}).get("error")
                },
                "ssh": {
                    "ssh_ident": port.get("ssh", {}).get("ssh_ident")
                }
            }

            print(f"Adding result: {result}")
            results.append(result)

    print(f"Total results generated: {len(results)}")
    summary = f"{meta.get('scanned_hosts', 0)} hosts scanned. {meta.get('alive_hosts', 0)} alive."

    return jsonify({
        "title": "Scan Report",
        "summary": summary,
        "meta": meta,
        "results": results
    })

@app.route("/api/download/<filetype>")
def download(filetype):
    """Allows downloading scan.json, scan.csv, or scan.pdf from /reports."""
    print(f"Download request: {filetype}")
    if filetype not in ("json", "csv", "pdf"):
        return jsonify({"error": "Invalid file type"}), 400

    files = sorted(REPORTS_DIR.glob(f"scan*.{filetype}"), reverse=True)
    if not files:
        return jsonify({"error": f"No {filetype.upper()} report found"}), 404

    print(f"Sending: {files[0].name}")
    return send_from_directory(REPORTS_DIR, files[0].name, as_attachment=True)

@app.route("/api/static/<filename>")
def serve_asset(filename):
    """Serves static assets like charts and CSV from /frontend/assets."""
    return send_from_directory(ASSETS_DIR, filename)

@app.route("/")
def serve_report_html():
    """Serves the main HTML report page."""
    return send_from_directory(FRONTEND_DIR, "report.html")

if __name__ == "__main__":
    app.run(debug=True)
