<div align="center">

```
  ███████╗ █████╗  ██████╗ ██╗     ███████╗    ███████╗██╗   ██╗███████╗███████╗
  ██╔════╝██╔══██╗██╔════╝ ██║     ██╔════╝    ██╔════╝╚██╗ ██╔╝██╔════╝██╔════╝
  █████╗  ███████║██║  ███╗██║     █████╗      █████╗   ╚████╔╝ █████╗  ███████╗
  ██╔══╝  ██╔══██║██║   ██║██║     ██╔══╝      ██╔══╝    ╚██╔╝  ██╔══╝  ╚════██║
  ███████╗██║  ██║╚██████╔╝███████╗███████╗    ███████╗   ██║   ███████╗███████║
  ╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚══════╝    ╚══════╝   ╚═╝   ╚══════╝╚══════╝
```

**Pentest Host Discovery Engine**

![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=flat-square&logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-Linux-FCC624?style=flat-square&logo=linux&logoColor=black)

</div>

---

## Overview

EagleEyes is a modular host discovery engine built for penetration testers. It finds live hosts, enumerates open ports, and extracts domain names — across anything from a single IP to a full /8 network.

It runs passive OSINT before touching the target, then applies multi-method active discovery with a confidence score per host, and produces clean reports in TXT, JSON, CSV, and HTML.

---

## ⚡ Quick Start

```bash
git clone https://github.com/msecurity0/eagleeyes.git && cd eagleeyes
pip install -r requirements.txt
sudo apt install nmap masscan arp-scan

python eagle_scan.py 192.168.1.0/24
```

---

## 🔍 How It Works

| Phase | What happens |
|-------|-------------|
| **0 — Input** | Parses CIDR, IP ranges, domains, and mixed files. Lazy generator for /8 — never loads 16M IPs into RAM. |
| **1 — Passive** | Queries Shodan InternetDB, BGPView, ipinfo.io, Censys, crt.sh before any packet is sent to the target. |
| **2 — Discovery** | masscan ping sweep + nmap multi-probe (ICMP, TCP, UDP) + ARP on local nets. Each host gets a confidence score. |
| **3 — Ports** | masscan fast pass (top-1000), then nmap `-sV` on open ports only. Optional UDP on critical ports. |
| **4 — Services** | nmap NSE scripts, OS fingerprinting, banner grabbing. |
| **5 — Domains** | PTR/rDNS, SSL cert CN+SANs, HTTP headers, crt.sh certificate transparency fan-out. |
| **6 — Output** | Colored terminal + `results.txt` / `results.json` / `results.csv` / `report.html` |

### Confidence Scoring

Instead of binary alive/dead, every host gets a score from the methods that agreed:

| Method | Weight |
|--------|--------|
| ARP reply | 1.0 — definitive on local nets |
| ICMP echo-reply | 0.6 |
| TCP SYN-ACK | 0.5 per port |
| UDP response | 0.3 |
| Passive hint (Shodan) | 0.4 |

Default threshold: `0.5` (configurable with `--confidence`)

### Scale

| Subnet | Hosts | Strategy | Est. Time |
|--------|-------|----------|-----------|
| /30 – /24 | ≤ 256 | nmap only | < 2 min |
| /24 – /16 | ≤ 65K | masscan + nmap verify | 5 – 15 min |
| /16 – /8 | 65K+ | masscan at 100k pps, nmap on alive only | 30 – 60 min |

---

## 📦 Requirements

```bash
# Python deps
pip install -r requirements.txt

# System tools
sudo apt install nmap masscan arp-scan
```

> Tools are auto-detected. The scanner degrades gracefully if masscan or arp-scan are missing.

---

## 🚀 Usage

```bash
# Single subnet
python eagle_scan.py 192.168.1.0/24

# Large subnet, masscan only (no nmap deep scan)
python eagle_scan.py 10.0.0.0/8 --rate 100000 --fast-only

# Mixed targets: file + CLI
python eagle_scan.py @targets.txt 10.10.0.0/16 example.com

# Include UDP scan + custom port range
python eagle_scan.py 192.168.0.0/24 --udp --ports top100

# Host discovery only, skip port scan
python eagle_scan.py 10.0.0.0/16 --ping-only

# With API keys
python eagle_scan.py 10.0.0.0/24 \
  --shodan-key API_KEY \
  --censys-id ID --censys-secret SECRET

# Resume interrupted scan
python eagle_scan.py 10.0.0.0/8 \
  --resume eagleeyes_results/eagleeyes-20260615-1430/checkpoint.json
```

---

## ⚙️ Options

```
Targets
  CIDR            10.0.0.0/8
  Range           192.168.1.1-254
  Single IP       10.0.0.5
  Domain          example.com
  File            @targets.txt  (any mix of the above)
```

| Flag | Default | Description |
|------|---------|-------------|
| `--phase` | all | Run only: `passive,discovery,ports,domains,output` |
| `--skip-phase` | — | Skip specific phase(s) |
| `--resume FILE` | — | Resume from `checkpoint.json` |
| `--no-passive` | off | Skip all API lookups |
| `--ping-only` | off | Stop after host discovery |
| `--confidence` | 0.5 | Min score to mark host alive |
| `--ports` | top1000 | `top100` / `top1000` / `all` / `80,443` |
| `--udp` | off | Scan critical UDP ports |
| `--fast-only` | off | masscan only, no nmap service scan |
| `--rate` | 50000 | masscan packets/sec |
| `--format` | all | `txt,json,csv,html` |
| `--output DIR` | `./eagleeyes_results` | Output directory |
| `--no-color` | off | Disable ANSI output |
| `--quiet` | off | Silent mode (files only) |
| `--concurrency` | 200 | Async task limit |
| `--timeout` | 10 | Per-host timeout (seconds) |
| `--shodan-key` | — | Shodan API key |
| `--censys-id/secret` | — | Censys credentials |
| `--ipinfo-key` | — | ipinfo.io token |

---

## 🔑 Passive Data Sources

| Source | Free | Key Needed | Data |
|--------|------|-----------|------|
| [Shodan InternetDB](https://internetdb.shodan.io) | ✅ | No | Ports, CVEs, hostnames, CPEs |
| [BGPView](https://bgpview.io) | ✅ | No | ASN, prefix, ISP, country |
| [ipinfo.io](https://ipinfo.io) | ✅ | Optional | Geo, org, ASN |
| [crt.sh](https://crt.sh) | ✅ | No | Certificate transparency domains |
| [Shodan API](https://shodan.io) | ❌ | Yes | Full historical host data |
| [Censys](https://censys.io) | ⚡ | Yes (250/mo free) | Deep host intelligence |

---

## 📁 Output

Each scan writes to `eagleeyes_results/<scan-id>/`:

```
results.txt          readable report
results.json         full data (machine-readable)
results.csv          one row per open port
ip_domain_map.csv    IP → domain mappings with source
report.html          sortable/filterable dark-theme report
checkpoint.json      resume state (saved after each phase)
scan_metadata.json   timing, stats, config used
```

The HTML report is **fully self-contained** — no internet needed to view it.

---

## 🗂️ Structure

```
eagle_scan.py              entry point + orchestrator
config.yml                 settings & API keys
modules/
  config.py                config loader, tool detection
  input_parser.py          target parsing
  passive_recon.py         API lookups (Shodan, BGP, ipinfo, Censys, crt.sh)
  host_discovery.py        masscan + nmap + ARP, confidence scoring
  port_scanner.py          masscan fast pass + nmap -sV + UDP
  domain_extractor.py      PTR, SSL SANs, HTTP, crt.sh
  output.py                terminal, TXT, JSON, CSV, HTML
```

---

## License

MIT
