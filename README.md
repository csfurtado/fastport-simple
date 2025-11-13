# FastPort — Fast Asynchronous Port and Service Scanner

FastPort is a high-performance network scanning tool built in **Python 3.10+**, designed for asynchronous port and service enumeration. It leverages `asyncio` and `aiohttp` for parallel scanning and produces structured reports in **JSON**, **CSV**, and **PDF** formats. A web-based interface is included for interactive visualization.

---

## Features

- Fast scanning of individual IPs or entire subnets (CIDR notation)
- Detection of open ports and associated services
- Optional extraction of HTTP headers, TLS certificate metadata, and SSH fingerprints
- Automatic generation of structured reports:
  - `scan.json` — full structured output
  - `scan.csv` — tabular format
  - `scan.pdf` — formatted printable report
- Web interface for viewing scan results (`report.html`)
- Compatible with Linux, macOS, and WSL environments

---

## Installation

Clone the repository and install dependencies:

```bash
git clone https://github.com/yourusername/fastport-project.git
cd fastport-project
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```
---

## Project Structure

fastport-project/
├── main.py                  # Entry point for scanning execution
├── LICENSE
├── requirements.txt         # Python dependencies
├── roadmap.md               # Development roadmap
├── fastport/                # Core scanning and reporting modules
│   ├── __init__.py
│   ├── scanner.py           # Asynchronous port scanner logic
│   ├── output_all.py        # Orchestration of all output formats
│   ├── output_json.py       # JSON report generation
│   ├── output_csv.py        # CSV report generation
│   ├── output_pdf.py        # PDF report generation using fpdf
│   ├── utils.py             # Utility functions (IP parsing, CIDR expansion, etc.)
│   └── probes.py            # Protocol-specific probes (HTTP, TLS, SSH)
├── api/                     # Web API and frontend
│   ├── __init__.py
│   ├── api.py               # Flask API endpoints for data access and download
│   ├── visuals.py           # Chart generation and visual summaries
│   └── frontend/
│       ├── report.html      # Interactive HTML report
│       └── assets/          # Static assets (charts, styles, etc.)
└── reports/                 # Output directory for generated reports
    ├── scan.json
    ├── scan.csv
    └── scan.pdf

---

## Module Details

main.py : Handles CLI arguments, orchestrates scanning, and triggers report generation. Supports CIDR input and optional metadata extraction.
	
scanner.py : Implements asynchronous port scanning using asyncio and aiohttp. Manages host discovery, port probing, and service detection.

output_all.py : Coordinates the generation of all report formats (JSON, CSV, PDF) after scanning is complete.

output_json.py : Serializes scan results into structured JSON format, including metadata and per-host service details.

output_csv.py : Generates a flat CSV file for easy tabular analysis or spreadsheet import.

output_pdf.py : Creates a formatted PDF report using fpdf, suitable for sharing or printing.

utils.py: Provides helper functions for:  IP and CIDR parsing; Host validation; Timing and progress tracking; Data normalization

probes.py : Contains protocol-specific probes for:  
	HTTP: title extraction, header parsing;  
	TLS: certificate metadata and error handling;   
	SSH: fingerprint and banner identification

api.py: Defines Flask routes for:
	Serving the latest scan results via /api/report
	Downloading reports in various formats
	Serving static assets and the main HTML report

visuals.py: Generates visual summaries (e.g., charts) from scan data using matplotlib. Assets are saved to the frontend for display.

report.html: Interactive web report that displays scan results in a sortable table with optional charts and metadata.

---

## Dependencies

fpdf           # PDF report generation
flask          # Web API framework
flask-cors     # CORS support for API
aiohttp        # Asynchronous HTTP client
matplotlib     # Chart generation
tqdm           # Progress bars

---

## Roadmap

Future development plans are documented in roadmap.md, including:

    Directory scanning integration

    CVE mapping based on service versions

    ChatGPT-powered vulnerability summaries

    QR code generation for mobile access

    Graphviz-based relationship visualization

    Scan diffing and historical comparison

    Integration with fastport-site and fastport-comments
    
---

## Contributing

Pull requests are welcome. Please refer to roadmap.md for planned features and open tasks. For bug reports or suggestions, open an issue on GitHub.

---

## License

This project is licensed under the terms of the MIT License.


