import json
from pathlib import Path
from datetime import datetime
from typing import Any, Dict
from fpdf import FPDF

# Diretório base e relatórios
BASE_DIR = Path(__file__).resolve().parents[1]
REPORTS_DIR = BASE_DIR / "reports"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)


def _ensure_parent(filepath: Path):
    """Garante que o diretório do ficheiro existe."""
    filepath.parent.mkdir(parents=True, exist_ok=True)


def save_json(results: Dict[str, Any], filename: str = "scan.json") -> str:
    """Guarda os resultados do scan em formato JSON dentro de /reports."""
    filepath = REPORTS_DIR / filename
    _ensure_parent(filepath)

    out = {
        "meta": {
            "timestamp": datetime.utcnow().isoformat(),
            "scanned_hosts": len(results),
            "alive_hosts": sum(1 for r in results.values() if r.get("open_ports")),
        },
        "hosts": results,
    }

    with open(filepath, "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2, ensure_ascii=False)

    return str(filepath.resolve())


class ReportPDF(FPDF):
    """Classe personalizada para o relatório PDF (com suporte Unicode)."""

    def __init__(self):
        super().__init__()
        # Suporte a UTF-8 (necessita fonte TTF)
        font_path = Path(__file__).resolve().parent / "DejaVuSans.ttf"
        if font_path.exists():
            self.add_font("DejaVu", "", str(font_path), uni=True)
            self.add_font("DejaVu", "B", str(font_path), uni=True)
            self.font_family = "DejaVu"
        else:
            self.font_family = "Helvetica"

    def header(self):
        self.set_font(self.font_family, style="B", size=14)
        self.cell(0, 10, "FastPort - Relatório de Varrimento", ln=True, align="C")
        self.ln(4)
        self.set_font(self.font_family, size=10)
        self.cell(0, 8, f"Gerado em: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True, align="C")
        self.ln(6)

    def footer(self):
        self.set_y(-15)
        self.set_font(self.font_family, size=8)
        self.cell(0, 10, f"Página {self.page_no()} / {{nb}}", align="C")


def save_pdf(results: Dict[str, Any], filename: str = "scan.pdf") -> str:
    """Gera um relatório PDF detalhado e visualmente agradável."""
    filepath = REPORTS_DIR / filename
    _ensure_parent(filepath)

    pdf = ReportPDF()
    pdf.alias_nb_pages()
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.set_font(pdf.font_family, size=11)

    total_hosts = len(results)
    active_hosts = sum(1 for r in results.values() if r.get("open_ports"))

    # Resumo inicial
    pdf.set_fill_color(230, 230, 255)
    pdf.cell(0, 10, f"Resumo: {active_hosts} de {total_hosts} hosts estão ativos.", ln=True, fill=True)
    pdf.ln(8)

    for host, data in results.items():
        ports = data.get("open_ports", [])
        if not ports:
            continue

        # Cabeçalho do host
        pdf.set_fill_color(220, 235, 220)
        pdf.set_draw_color(100, 100, 100)
        pdf.set_line_width(0.4)
        pdf.set_font(pdf.font_family, "B", 12)
        pdf.cell(0, 10, f"Host: {host}", ln=True, fill=True, border=1)
        pdf.ln(3)

        for port_data in ports:
            port = port_data.get("port")
            proto = port_data.get("protocol", "tcp")
            state = port_data.get("state", "desconhecido")
            service = port_data.get("service")
            banner = port_data.get("banner")
            version = port_data.get("version")
            cves = port_data.get("cves")
            tls = port_data.get("tls_cert")
            http = port_data.get("http")
            ssh = port_data.get("ssh")
            ascii_preview = port_data.get("ascii_preview")

            pdf.set_font(pdf.font_family, "B", 11)
            pdf.multi_cell(0, 7, f"  Porta {port}/{proto} - {state}", border=0)
            pdf.set_font(pdf.font_family, size=10)

            def add_field(label: str, value: Any, max_len: int = 400):
                """Função auxiliar para imprimir campos apenas se existirem."""
                if value:
                    if isinstance(value, (dict, list)):
                        value = json.dumps(value, ensure_ascii=False, indent=2)
                    elif isinstance(value, str) and len(value) > max_len:
                        value = value[:max_len] + "..."
                    pdf.multi_cell(0, 6, f"    {label}: {value}")

            add_field("Serviço", service)
            add_field("Versão", version)
            add_field("Banner", banner)
            add_field("CVEs", ", ".join(cves) if isinstance(cves, list) else cves)
            add_field("TLS", tls)
            add_field("HTTP", http)
            add_field("SSH", ssh)
            add_field("Preview ASCII", ascii_preview)

            pdf.ln(3)

        pdf.ln(4)
        pdf.cell(0, 0, "", ln=True, border="B")
        pdf.ln(5)

    pdf.output(str(filepath))
    return str(filepath.resolve())
