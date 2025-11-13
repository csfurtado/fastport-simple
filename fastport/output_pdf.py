from pathlib import Path
from datetime import datetime
from typing import Any, Dict, Optional
from fpdf import FPDF
from io import BytesIO
import hashlib

# matplotlib is optional — charts will be created only if available
try:
    import matplotlib.pyplot as plt
    HAVE_MPL = True
except Exception:
    HAVE_MPL = False

BASE_DIR = Path(__file__).resolve().parents[1]
REPORTS_DIR = BASE_DIR / "reports"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

def _timestamped_name(base: str, ext: str) -> str:
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    return f"{base}-{ts}.{ext}"

def sanitize_label(x: Any, max_len: int = 30) -> str:
    if x is None:
        return "unknown"
    s = str(x)
    safe_chars = [(ch if 32 <= ord(ch) <= 126 else ".") for ch in s]
    out = "".join(safe_chars).strip()
    if not out:
        out = "unknown"
    return out[:max_len-3] + "..." if len(out) > max_len else out

class ReportPDF(FPDF):
    def __init__(self):
        super().__init__()
        self.set_auto_page_break(auto=True, margin=15)
        font_path = Path(__file__).resolve().parent / "DejaVuSans.ttf"
        self.unicode_font = False

        if font_path.exists():
            try:
                # Nome único para evitar reutilização de fontes antigas
                unique_font_name = f"DejaVu_{hashlib.md5(str(font_path).encode()).hexdigest()[:6]}"
                self.font_family = unique_font_name
                self.add_font(self.font_family, "", str(font_path), uni=True)
                self.add_font(self.font_family, "B", str(font_path), uni=True)
                self.unicode_font = True
            except Exception as e:
                print(f"Erro ao carregar fonte personalizada: {e}")
                self.font_family = "Helvetica"
        else:
            print(f"Fonte não encontrada em: {font_path}")
            self.font_family = "Helvetica"


    def header(self):
        if self.page_no() == 1:
            return
        self.set_font(self.font_family, "B", 12)
        self.cell(0, 10, "FastPort Reconnaissance Report", ln=True, align="C")
        self.ln(2)
        self.set_font(self.font_family, size=9)
        self.cell(0, 6, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True, align="C")
        self.ln(3)

    def footer(self):
        self.set_y(-15)
        self.set_font(self.font_family, size=8)
        self.cell(0, 10, f"Page {self.page_no()} / {{nb}}", align="C")

    def section_title(self, title: str):
        self.set_font(self.font_family, "B", 12)
        self.set_fill_color(230, 230, 255)
        self.cell(0, 8, self._safe_text(title), ln=True, fill=True)
        self.ln(3)

    def subsection_title(self, title: str):
        self.set_font(self.font_family, "B", 11)
        self.set_text_color(30, 30, 30)
        self.cell(0, 7, self._safe_text(title), ln=True)
        self.set_text_color(0, 0, 0)
        self.ln(2)

    def _safe_text(self, text: Optional[str]) -> str:
        if text is None:
            return ""
        if self.unicode_font:
            return str(text)
        return text.encode("latin-1", errors="replace").decode("latin-1")

    def add_chart(self, title: str, data_dict: Dict[str, Any]):
        if not HAVE_MPL or not data_dict:
            return
        keys_raw = list(data_dict.keys())
        values = list(data_dict.values())
        labels = [sanitize_label(k, max_len=25) for k in keys_raw]
        try:
            fig, ax = plt.subplots(figsize=(4, 2.5))
            if len(labels) <= 5:
                ax.pie(values, labels=labels, autopct="%1.1f%%", startangle=140)
            else:
                ax.bar(range(len(values)), values, tick_label=labels)
                plt.xticks(rotation=30, ha="right")
            ax.set_title(sanitize_label(title, max_len=60))
            plt.tight_layout()
            buf = BytesIO()
            plt.savefig(buf, format="png", dpi=120)
            plt.close(fig)
            buf.seek(0)
            page_width = self.w - 2 * self.l_margin
            img_width = 150
            x_pos = (page_width - img_width) / 2 + self.l_margin
            self.image(buf, x=x_pos, w=img_width)
            self.ln(12)
        except Exception:
            try:
                plt.close(fig)
            except Exception:
                pass

def _flatten_os_guess(os_guess: Any) -> str:
    if not os_guess:
        return ""
    if isinstance(os_guess, dict):
        return f"{os_guess.get('family','')};{os_guess.get('confidence','')}"
    return str(os_guess)

def _write_multiline_safe(pdf: ReportPDF, text: str, max_len=400, h=5):
    if not text:
        return
    txt = text if len(text) <= max_len else text[:max_len] + "..."
    pdf.multi_cell(0, h, pdf._safe_text(txt))

def save_pdf(results: Dict[str, Any], filename: Optional[str] = None, author: str = "FastPort Scanner") -> str:
    if not filename:
        filename = _timestamped_name("scan", "pdf")
    filepath = REPORTS_DIR / filename

    pdf = ReportPDF()
    pdf.alias_nb_pages()

    # COVER
    pdf.add_page()
    pdf.set_font(pdf.font_family, "B", 22)
    pdf.cell(0, 20, pdf._safe_text("FastPort Network Reconnaissance Report"), ln=True, align="C")
    pdf.ln(12)
    pdf.set_font(pdf.font_family, size=11)
    pdf.multi_cell(0, 7, pdf._safe_text(
        "This report summarizes host discovery and service enumeration results "
        "generated by the FastPort asynchronous scanning engine."
    ), align="C")
    pdf.ln(8)
    pdf.set_font(pdf.font_family, size=10)
    pdf.cell(0, 6, pdf._safe_text(f"Generated by: {author}"), ln=True, align="C")
    pdf.cell(0, 6, pdf._safe_text(f"Date (UTC): {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}"), ln=True, align="C")
    pdf.cell(0, 6, pdf._safe_text(f"Total Hosts Scanned: {len(results)}"), ln=True, align="C")

    # EXECUTIVE SUMMARY
    pdf.add_page()
    pdf.section_title("Executive Summary")
    total_hosts = len(results)
    active_hosts = sum(1 for r in results.values() if r.get("ports"))
    total_ports = sum(len(r.get("ports", [])) for r in results.values())
    pdf.set_font(pdf.font_family, size=11)
    pdf.multi_cell(0, 7, pdf._safe_text(
        f"FastPort performed a reconnaissance scan of {total_hosts} target hosts. "
        f"{active_hosts} hosts responded with one or more open ports, totalling {total_ports} open service endpoints."
    ))
    pdf.ln(6)
    pdf.add_chart("Host Activity Overview", {"Active": active_hosts, "Inactive": max(total_hosts - active_hosts, 0)})

    # DETAILED HOST RESULTS
    pdf.add_page()
    pdf.section_title("Host Details")
    for host, data in results.items():
        ports = data.get("ports", [])
        if not ports:
            continue
        pdf.subsection_title(f"{host} ({len(ports)} open ports)")
        for p in ports:
            port = p.get("port")
            proto = p.get("protocol", "tcp")
            state = p.get("state", "unknown")
            service = p.get("service") or ""
            banner = p.get("banner") or p.get("ascii_preview") or ""
            version = p.get("version") or ""
            fingerprint = p.get("fingerprint") or ""
            os_guess = _flatten_os_guess(p.get("os_guess"))
            pdf.set_font(pdf.font_family, "B", 10)
            pdf.cell(0, 6, pdf._safe_text(f"Port {port}/{proto} ({state})"), ln=True)
            pdf.set_font(pdf.font_family, size=9)
            pdf.cell(0, 6, pdf._safe_text(f"Service: {service}"), ln=True)
            if version:
                pdf.cell(0, 6, pdf._safe_text(f"Version: {version}"), ln=True)
            if fingerprint:
                pdf.cell(0, 6, pdf._safe_text(f"Fingerprint: {fingerprint}"), ln=True)
            if os_guess:
                pdf.cell(0, 6, pdf._safe_text(f"OS Guess: {os_guess}"), ln=True)
            if banner:
                _write_multiline_safe(pdf, banner, max_len=400)
            http_title = (p.get("http") or {}).get("title")
            if http_title:
                pdf.cell(0, 5, pdf._safe_text(f"HTTP Title: {http_title}"), ln=True)
            tls_sha = (p.get("tls_cert") or {}).get("sha256")
            if tls_sha:
                pdf.cell(0, 5, pdf._safe_text(f"TLS Cert SHA256: {tls_sha}"), ln=True)

            pdf.ln(3)
        pdf.ln(4)
        pdf.cell(0, 0, "", ln=True, border="B")
        pdf.ln(6)

    # STATS SUMMARY
    pdf.add_page()
    pdf.section_title("Scan Statistics")
    services_count: Dict[str, int] = {}
    ports_by_proto: Dict[str, int] = {}
    for hdata in results.values():
        for p in hdata.get("ports", []):
            svc = p.get("service") or "unknown"
            services_count[svc] = services_count.get(svc, 0) + 1
            proto = p.get("protocol", "tcp")
            ports_by_proto[proto] = ports_by_proto.get(proto, 0) + 1

    if services_count:
        pdf.add_chart("Service Distribution", services_count)
    if ports_by_proto:
        pdf.add_chart("Protocol Distribution", ports_by_proto)

    pdf.output(str(filepath))
    return str(filepath.resolve())
