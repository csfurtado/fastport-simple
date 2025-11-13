import matplotlib.pyplot as plt
from collections import Counter
from pathlib import Path
import csv

def generate_visuals(grouped_data: dict, output_dir: Path):
    """
    Generates bar chart, pie chart, and CSV summary from grouped scan data.

    Args:
        grouped_data (dict): Dictionary structured as {ip: {"ports": [...]}}.
        output_dir (Path): Directory to save generated files.
    """
    services = []
    table = []

    for host, info in grouped_data.items():
        for port in info.get("ports", []):
            if not isinstance(port, dict):
                continue
            number = port.get("port")
            if number is None:
                continue
            service = port.get("service", "unknown")
            state = port.get("state", "unknown")
            version = port.get("version", "")
            banner = port.get("banner", "")
            services.append(service)
            table.append((host, number, service, state, version, banner))

    counts = Counter(services)
    print(f"Services found: {dict(counts)}")

    output_dir.mkdir(parents=True, exist_ok=True)

    if not counts:
        print("No services found — skipping chart generation.")
        return

    # Bar chart: Ports per Service
    try:
        plt.figure(figsize=(10, 6))
        plt.bar(counts.keys(), counts.values(), color="steelblue")
        plt.title("Ports per Service")
        plt.xlabel("Service")
        plt.ylabel("Number of Ports")
        plt.xticks(rotation=45, ha="right", fontsize=10)
        plt.tight_layout()
        plt.savefig(output_dir / "port_chart.png")
        plt.close()
    except Exception as e:
        print(f"Error generating bar chart: {e}")

    # Pie chart: Service Distribution
    try:
        plt.figure(figsize=(7, 7))
        plt.pie(
            counts.values(),
            labels=counts.keys(),
            autopct="%1.1f%%",
            startangle=140,
            textprops={"fontsize": 10}
        )
        plt.title("Service Distribution")
        plt.tight_layout()
        plt.savefig(output_dir / "service_pie.png")
        plt.close()
    except Exception as e:
        print(f"Error generating pie chart: {e}")

    # CSV summary table
    try:
        table_path = output_dir / "port_table.csv"
        with open(table_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Host", "Port", "Service", "State", "Version", "Banner"])
            writer.writerows(table)
    except Exception as e:
        print(f"Error generating CSV: {e}")
