from .output_json import save_json
from .output_csv import save_csv
from .output_pdf import save_pdf

def save_all_reports(results, base_name=None):
    base = base_name if base_name else "scan"
    json_name = f"{base}.json"
    csv_name = f"{base}.csv"
    pdf_name = f"{base}.pdf"

    paths = {
        "json": save_json(results, json_name),
        "csv": save_csv(results, csv_name),
        "pdf": save_pdf(results, pdf_name),
    }
    return paths
