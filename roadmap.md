# FastPort Project — Technical Roadmap

## Phase 1: Advanced Reconnaissance Features

- **Integrate directory scanning**
  - Discover hidden directories and folders on HTTP servers
  - Include results in `scan.json` and display them in `report.html`

- **Map service versions to known CVEs**
  - Use local database (NVD JSON) or public APIs (Vulners, ExploitDB)
  - Add a `cves` field per service in the report

- **Integrate ChatGPT for vulnerability analysis**
  - Generate technical summaries based on `scan.json` data
  - Include the analysis in `report.html` as an “Intelligent Analysis” section

## Phase 2: Visualization and Usability

- **Generate Graphviz (.dot) file for relationship mapping**
  - Visualize host ↔ services ↔ subdomains
  - Export as `.dot` and `.png`, and include in the report

- **Implement scan diffs**
  - Compare current results with previous scans
  - List changes: new ports, removed services, modified versions

- **Generate QR code for mobile access to the report**
  - Create a QR code pointing to `report.html`
  - Display it at the top of the page for quick mobile access

## Phase 3: Orchestration and Safety

- **Integrate Nmap NSE scripts as an advanced mode**
  - Allow script selection by service type (e.g., `http-enum`, `ssl-cert`)
  - Include script results in `scan.json` and the report

- **Implement rate control and safety flags**
  - Limit hosts per minute and add delays between requests
  - Add a `--safe` mode for non-intrusive scans

## Phase 4: Export, Integration, and Collaboration

- **Export report to remote format with authentication**
  - Secure web access via login or token

- **Integrate with `fastport-site`**
  - Automatically publish reports to the web portal
  - Centralized view of multiple scans

- **Integrate with `fastport-comments`**
  - Enable collaborative comments per host or service
  - Record technical notes and suggestions from users

- **Add interactive filters to the frontend**
  - Filter by IP, service, risk, or CVE directly in `report.html`

- **Support custom plugins**
  - Allow users to add their own analysis or visualization modules
