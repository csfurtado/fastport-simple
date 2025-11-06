# FastPort — Fast Asynchronous Port Scanner

FastPort é uma ferramenta rápida de varrimento de portas e serviços em redes, escrita em **Python 3.10+**, que utiliza **asyncio** para varredura paralela e gera relatórios automáticos em **JSON** e **PDF**.

---

## Funcionalidades

- Varrimento rápido de IPs ou sub-redes (`CIDR`)
- Detecção de serviços e banners
- Extração opcional de metadados HTTP, TLS e SSH
- Geração automática de relatórios:
  - **JSON estruturado** (`reports/scan.json`)
  - **PDF formatado** (`reports/scan.pdf`)
- Compatível com Linux, macOS e WSL

---

## Instalação

```bash
git clone https://github.com/seuusuario/fastport-project.git
cd fastport-project
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```
---

## Estrutura

fastport-project/
├── main.py
├── LICENSE
├── fastport/
│   ├── __init__.py
│   ├── scanner.py
│   ├── output.py
│   ├── utils.py
│   └── probes.py
└── reports/
    ├── scan.json
    └── scan.pdf
