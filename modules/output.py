
import csv
import json
import os
from datetime import datetime, timezone
from pathlib import Path

RESET  = "\033[0m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
BLUE   = "\033[94m"
MAGENTA= "\033[95m"
CYAN   = "\033[96m"
WHITE  = "\033[97m"
GRAY   = "\033[90m"

def c(color: str, text: str, bold: bool = False) -> str:
    prefix = BOLD if bold else ""
    return f"{prefix}{color}{text}{RESET}"

def _color_port(port: int) -> str:
    critical = {21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 3306, 3389, 5432, 6379, 27017}
    if port in critical:
        return RED
    if port in range(8000, 9000):
        return YELLOW
    return GREEN

BANNER = (
    f"\n{CYAN}{BOLD}"
    "  ███████╗ █████╗  ██████╗ ██╗     ███████╗    ███████╗██╗   ██╗███████╗███████╗\n"
    "  ██╔════╝██╔══██╗██╔════╝ ██║     ██╔════╝    ██╔════╝╚██╗ ██╔╝██╔════╝██╔════╝\n"
    "  █████╗  ███████║██║  ███╗██║     █████╗      █████╗   ╚████╔╝ █████╗  ███████╗\n"
    "  ██╔══╝  ██╔══██║██║   ██║██║     ██╔══╝      ██╔══╝    ╚██╔╝  ██╔══╝  ╚════██║\n"
    "  ███████╗██║  ██║╚██████╔╝███████╗███████╗    ███████╗   ██║   ███████╗███████║\n"
    f"  ╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚══════╝    ╚══════╝   ╚═╝   ╚══════╝╚══════╝{RESET}\n"
    f"  {GRAY}Host Discovery Engine{RESET}  {YELLOW}v5.0{RESET}\n"
)

def print_banner() -> None:
    print(BANNER)

def print_scan_config(state: dict, api_status: dict, tool_status: dict, warnings: list[str]) -> None:
    meta = state["meta"]
    print(f"  {c(GRAY,'Scan ID')}     {c(WHITE, meta['scan_id'])}")
    print(f"  {c(GRAY,'Targets')}     {c(YELLOW, str(state['stats']['total_targets']))} hosts")
    print(f"  {c(GRAY,'Phases')}      {c(WHITE, ', '.join(meta.get('phases', ['all'])))}")
    print()
    print(f"  {c(GRAY,'Tools')}")
    for tool, path in tool_status.items():
        status = c(GREEN, f"✔  {path}") if path else c(RED, "✘  not found")
        print(f"    {c(YELLOW, f'{tool:<12}')} {status}")
    print()
    print(f"  {c(GRAY,'APIs')}")
    status_colors = {"free": GREEN, "paid": CYAN, "free_limited": YELLOW, "unavailable": GRAY, "free_token": GREEN}
    for api, status in api_status.items():
        color = status_colors.get(status, WHITE)
        print(f"    {c(YELLOW, f'{api:<20}')} {c(color, status)}")
    if warnings:
        print()
        for w in warnings:
            print(f"  {c(YELLOW, '⚠')}  {c(GRAY, w)}")
    print()

def print_host_alive(ip: str, methods: list[str], confidence: float, color: bool = True) -> None:
    conf_color = GREEN if confidence >= 0.7 else YELLOW if confidence >= 0.5 else GRAY
    meth_str = ", ".join(methods)
    print(f"  {c(GREEN, '●')} {c(WHITE, ip, bold=True)}  "
          f"{c(conf_color, f'confidence={confidence:.2f}')}  "
          f"{c(GRAY, f'({meth_str})')}")

def print_port(ip: str, port: int, proto: str, service: str, version: str) -> None:
    pc = _color_port(port)
    ver_str = f"  {c(GRAY, version)}" if version else ""
    print(f"    {c(pc, f'{port}/{proto}')}  {c(WHITE, service)}{ver_str}")

def print_phase_start(phase: str, detail: str = "") -> None:
    detail_str = f"  {c(GRAY, detail)}" if detail else ""
    print(f"\n  {c(BLUE, '▶', bold=True)} {c(WHITE, phase, bold=True)}{detail_str}")

def print_phase_done(phase: str, stats: str = "") -> None:
    print(f"  {c(GREEN, '✔')} {c(GRAY, phase)} complete  {c(WHITE, stats)}")

def print_final_summary(state: dict) -> None:
    stats = state["stats"]
    meta = state["meta"]
    elapsed = ""
    if meta.get("start_time") and meta.get("end_time"):
        try:
            start = datetime.fromisoformat(meta["start_time"])
            end = datetime.fromisoformat(meta["end_time"])
            secs = int((end - start).total_seconds())
            elapsed = f"{secs // 60}m {secs % 60}s"
        except Exception:
            pass

    print(f"\n  {c(GRAY, '─' * 68)}")
    print(f"  {c(WHITE, 'Summary', bold=True)}")
    print(f"    {c(GRAY,'Total targets')}  {c(WHITE, str(stats.get('total_targets', 0)))}")
    print(f"    {c(GRAY,'Alive hosts')}    {c(GREEN, str(stats.get('alive_hosts', 0)), bold=True)}")
    print(f"    {c(GRAY,'Open ports')}     {c(YELLOW, str(stats.get('open_ports_found', 0)))}")
    print(f"    {c(GRAY,'Domains found')} {c(CYAN, str(stats.get('domains_extracted', 0)))}")
    if elapsed:
        print(f"    {c(GRAY,'Elapsed')}        {c(WHITE, elapsed)}")
    print(f"  {c(GRAY, '─' * 68)}\n")

def print_alive_hosts_detail(state: dict) -> None:
    alive = [(ip, h) for ip, h in state["hosts"].items() if h.get("status") == "alive"]
    if not alive:
        return

    print(f"\n  {c(MAGENTA, '═' * 68, bold=True)}")
    for ip, host in sorted(alive, key=lambda x: _ip_sort_key(x[0])):
        conf_str = f"confidence={host['confidence']:.2f}"
        print(f"\n  {c(WHITE, ip, bold=True)}  {c(GREEN, '● ALIVE')}  "
              f"{c(GRAY, conf_str)}")
        print(f"  {c(GRAY, '─' * 48)}")

        asn = host.get("asn", {})
        if asn.get("org") or asn.get("number"):
            asn_str = f"{asn.get('number', '')} {asn.get('org', '')}".strip()
            loc = f"{asn.get('city', '')}, {asn.get('country', '')}".strip(", ")
            print(f"  {c(GRAY,'ASN/Org')}   {c(WHITE, asn_str)}")
            if loc:
                print(f"  {c(GRAY,'Location')}  {c(YELLOW, loc)}")
            if asn.get("is_cdn"):
                print(f"  {c(YELLOW,'⚠ CDN/Cloud detected — may not be the origin server')}")

        os_info = host.get("os", {})
        if os_info.get("guess"):
            acc_str = f"{os_info['accuracy']}% accuracy"
            print(f"  {c(GRAY,'OS')}        {c(MAGENTA, os_info['guess'])}  "
                  f"{c(GRAY, acc_str)}")

        tcp = host.get("ports", {}).get("tcp", {})
        if tcp:
            print(f"  {c(GRAY,'TCP Ports')}")
            for port in sorted(tcp.keys()):
                d = tcp[port]
                ver = f"{d.get('product','') or ''} {d.get('version','') or ''}".strip()
                if not ver:
                    ver = d.get("version", "")
                svc = d.get("service", "")
                print(f"    {c(_color_port(port), f'{port}', bold=True)}  "
                      f"{c(WHITE, svc or '?')}  {c(GRAY, ver)}")

                for script_id, output in d.get("scripts", {}).items():
                    first_line = output.strip().split("\n")[0][:80]
                    if first_line:
                        print(f"      {c(GRAY, f'[{script_id}]')} {c(DIM, first_line)}")

        udp = host.get("ports", {}).get("udp", {})
        if udp:
            print(f"  {c(GRAY,'UDP Ports')}")
            for port in sorted(udp.keys()):
                d = udp[port]
                print(f"    {c(YELLOW, f'{port}/udp')}  {c(WHITE, d.get('service', '?'))}  "
                      f"{c(GRAY, d.get('state', ''))}")

        domains = host.get("domains", {}).get("all", [])
        if domains:
            print(f"  {c(GRAY,'Domains')}   {c(CYAN, ', '.join(domains[:10]))}")
            if len(domains) > 10:
                print(f"             {c(GRAY, f'... +{len(domains)-10} more')}")

        vulns = host.get("vulns", [])
        if vulns:
            print(f"  {c(RED,'Vulns', bold=True)}")
            for v in vulns[:10]:
                cve = v.get("cve_id", "")
                src = v.get("source", "")
                print(f"    {c(RED, f'[{cve}]')}  {c(GRAY, f'source: {src}')}")

    print(f"\n  {c(MAGENTA, '═' * 68, bold=True)}")

def _ip_sort_key(ip: str):
    try:
        return tuple(int(p) for p in ip.split("."))
    except Exception:
        return (0, 0, 0, 0)

def write_txt(state: dict, filepath: str) -> None:
    lines = [
        "EagleEyes v5 — Host Discovery Report",
        f"Scan ID   : {state['meta']['scan_id']}",
        f"Generated : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"Targets   : {state['stats']['total_targets']}",
        f"Alive     : {state['stats']['alive_hosts']}",
        f"Open Ports: {state['stats']['open_ports_found']}",
        f"Domains   : {state['stats']['domains_extracted']}",
        "=" * 80, "",
    ]

    alive = [(ip, h) for ip, h in state["hosts"].items() if h.get("status") == "alive"]
    for ip, host in sorted(alive, key=lambda x: _ip_sort_key(x[0])):
        asn = host.get("asn", {})
        lines += [
            f"Host     : {ip}",
            f"Status   : ALIVE  (confidence={host['confidence']:.2f})",
            f"Methods  : {', '.join(host.get('discovery_methods', []))}",
            f"ASN      : {asn.get('number', 'N/A')} — {asn.get('org', 'N/A')}",
            f"Location : {asn.get('city', '')}, {asn.get('country', '')}".strip(", "),
            f"OS       : {host.get('os', {}).get('guess', 'N/A')}",
            f"Domains  : {', '.join(host.get('domains', {}).get('all', [])) or 'N/A'}",
        ]
        tcp = host.get("ports", {}).get("tcp", {})
        if tcp:
            lines.append("TCP Ports:")
            for port in sorted(tcp.keys()):
                d = tcp[port]
                ver = d.get("version", "")
                lines.append(f"  {port}/tcp  {d.get('service', '')}  {ver}")
        udp = host.get("ports", {}).get("udp", {})
        if udp:
            lines.append("UDP Ports:")
            for port in sorted(udp.keys()):
                d = udp[port]
                lines.append(f"  {port}/udp  {d.get('service', '')}  [{d.get('state', '')}]")
        vulns = host.get("vulns", [])
        if vulns:
            lines.append("Vulns:")
            for v in vulns:
                lines.append(f"  [{v.get('cve_id', '')}]  {v.get('source', '')}")
        lines += ["─" * 80, ""]

    Path(filepath).write_text("\n".join(lines), encoding="utf-8")

def write_json(state: dict, filepath: str) -> None:
    def default_serializer(obj):
        if isinstance(obj, set):
            return sorted(obj)
        return str(obj)

    data = {
        "meta": {**state["meta"], "schema_version": "5.0"},
        "stats": state["stats"],
        "hosts": {
            ip: h for ip, h in state["hosts"].items()
            if h.get("status") == "alive"
        },
        "bgp_prefixes": state.get("bgp_prefixes", {}),
    }
    Path(filepath).write_text(
        json.dumps(data, indent=2, default=default_serializer),
        encoding="utf-8",
    )

def write_csv(state: dict, dirpath: str) -> None:
    ports_file = os.path.join(dirpath, "results.csv")
    domains_file = os.path.join(dirpath, "ip_domain_map.csv")

    port_fields = ["ip", "confidence", "port", "proto", "service", "version",
                   "os_guess", "asn", "org", "country", "discovery_methods"]
    domain_fields = ["ip", "domain", "source"]

    with open(ports_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=port_fields)
        writer.writeheader()
        for ip, host in sorted(state["hosts"].items(), key=lambda x: _ip_sort_key(x[0])):
            if host.get("status") != "alive":
                continue
            asn = host.get("asn", {})
            base = {
                "ip": ip,
                "confidence": host.get("confidence", 0),
                "os_guess": host.get("os", {}).get("guess", ""),
                "asn": asn.get("number", ""),
                "org": asn.get("org", ""),
                "country": asn.get("country", ""),
                "discovery_methods": "|".join(host.get("discovery_methods", [])),
            }
            tcp = host.get("ports", {}).get("tcp", {})
            udp = host.get("ports", {}).get("udp", {})
            all_ports = [(p, "tcp", tcp[p]) for p in sorted(tcp)] + \
                        [(p, "udp", udp[p]) for p in sorted(udp)]
            if all_ports:
                for port, proto, d in all_ports:
                    writer.writerow({**base, "port": port, "proto": proto,
                                     "service": d.get("service", ""),
                                     "version": d.get("version", "")})
            else:
                writer.writerow({**base, "port": "", "proto": "", "service": "", "version": ""})

    with open(domains_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=domain_fields)
        writer.writeheader()
        for ip, host in sorted(state["hosts"].items(), key=lambda x: _ip_sort_key(x[0])):
            if host.get("status") != "alive":
                continue
            domains = host.get("domains", {})
            for domain in domains.get("ptr", []):
                writer.writerow({"ip": ip, "domain": domain, "source": "ptr"})
            for domain in domains.get("ssl_cn", []):
                writer.writerow({"ip": ip, "domain": domain, "source": "ssl_cn"})
            for domain in domains.get("ssl_sans", []):
                writer.writerow({"ip": ip, "domain": domain, "source": "ssl_san"})
            for domain in domains.get("crt_sh", []):
                writer.writerow({"ip": ip, "domain": domain, "source": "crt_sh"})
            for domain in domains.get("passive_api", []):
                writer.writerow({"ip": ip, "domain": domain, "source": "passive_api"})

def write_html(state: dict, filepath: str) -> None:
    stats = state["stats"]
    scan_id = state["meta"].get("scan_id", "")

    alive_hosts = [(ip, h) for ip, h in state["hosts"].items() if h.get("status") == "alive"]
    alive_hosts.sort(key=lambda x: _ip_sort_key(x[0]))

    rows_html = []
    for ip, host in alive_hosts:
        asn = host.get("asn", {})
        tcp_ports = sorted(host.get("ports", {}).get("tcp", {}).keys())
        domains = host.get("domains", {}).get("all", [])
        vulns = host.get("vulns", [])
        os_guess = host.get("os", {}).get("guess", "")
        conf = host.get("confidence", 0)
        conf_class = "high" if conf >= 0.7 else "med" if conf >= 0.5 else "low"
        ports_str = " ".join(
            f'<span class="port port-{_port_severity(p)}">{p}</span>' for p in tcp_ports
        )
        vuln_badges = "".join(
            f'<span class="vuln">{v["cve_id"]}</span>' for v in vulns
        )
        domains_str = ", ".join(domains[:5]) + (f" +{len(domains)-5}" if len(domains) > 5 else "")
        rows_html.append(f"""""")

    port_counter: dict[int, int] = {}
    for _, host in alive_hosts:
        for port in host.get("ports", {}).get("tcp", {}).keys():
            port_counter[port] = port_counter.get(port, 0) + 1
    top_ports = sorted(port_counter.items(), key=lambda x: -x[1])[:10]
    chart_labels = json.dumps([str(p[0]) for p in top_ports])
    chart_values = json.dumps([p[1] for p in top_ports])

    html = f
    max_count = top_ports[0][1] if top_ports else 1
    for port, count in top_ports:
        width = int((count / max_count) * 280)
        sev = _port_severity(port)
        html += f'    <div class="chart-bar"><span class="label">{port}</span><div class="bar port-{sev}" style="width:{width}px"></div><span class="count">{count}</span></div>\n'

    html += f
    Path(filepath).write_text(html, encoding="utf-8")

def _port_severity(port: int) -> str:
    critical = {21, 22, 23, 25, 135, 139, 445, 3389, 6379, 27017, 11211, 9200, 2181}
    if port in critical:
        return "crit"
    if port in range(8000, 9000) or port in {3306, 5432, 5900, 1433}:
        return "warn"
    return "ok"

def output_all(state: dict, config: dict) -> None:
    scan_id = state["meta"]["scan_id"]
    base_dir = Path(config["scan"]["output_dir"]) / scan_id
    base_dir.mkdir(parents=True, exist_ok=True)

    formats = config.get("output", {}).get("formats", ["txt", "json", "csv", "html"])

    if "txt" in formats:
        path = str(base_dir / "results.txt")
        write_txt(state, path)
        print(f"  {c(GREEN, '▸')} {c(CYAN, path)}")

    if "json" in formats:
        path = str(base_dir / "results.json")
        write_json(state, path)
        print(f"  {c(GREEN, '▸')} {c(CYAN, path)}")

    if "csv" in formats:
        write_csv(state, str(base_dir))
        print(f"  {c(GREEN, '▸')} {c(CYAN, str(base_dir / 'results.csv'))}")
        print(f"  {c(GREEN, '▸')} {c(CYAN, str(base_dir / 'ip_domain_map.csv'))}")

    if "html" in formats:
        path = str(base_dir / "report.html")
        write_html(state, path)
        print(f"  {c(GREEN, '▸')} {c(CYAN, path)}")

    meta_path = base_dir / "scan_metadata.json"
    meta_path.write_text(json.dumps({
        "scan_id": scan_id,
        "meta": state["meta"],
        "stats": state["stats"],
        "errors": state.get("errors", []),
    }, indent=2, default=str), encoding="utf-8")
