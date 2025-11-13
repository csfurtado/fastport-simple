import asyncio
from pathlib import Path
from fastport.scanner import scan_open_ports_then_probe
from fastport.utils import ip_range_from_cidr
from fastport.output_json import save_json
from fastport.output_csv import save_csv
from fastport.output_pdf import save_pdf


async def main():
    cidr = input("Enter target IP or CIDR: ").strip()
    hosts = ip_range_from_cidr(cidr)
    ports = list(range(1, 1025))  # ajustar para 65535 se quiser scan completo

    # Configurações de scanner
    concurrency = 500   # número de workers simultâneos
    timeout = 0.5       # timeout por conexão em segundos

    # Executa scan
    results = await scan_open_ports_then_probe(
        hosts,
        ports_spec=ports,
        protocols=("tcp",),  # usar ("udp",) se desejar UDP
        concurrency=concurrency,
        timeout=timeout,
        batch_hosts=20
    )

    # Diretório para relatórios
    base_dir = Path(__file__).resolve().parent
    reports_dir = base_dir / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)

    # Caminhos completos dos relatórios
    json_path = reports_dir / "scan.json"
    pdf_path = reports_dir / "scan.pdf"
    csv_path = reports_dir / "scan.csv"

    # Salva resultados
    save_json(results, json_path.name)
    save_pdf(results, pdf_path.name)
    save_csv(results, csv_path.name)

    print(f"\n Scan complete. {len(results)} hosts scanned.")

if __name__ == "__main__":
    asyncio.run(main())
