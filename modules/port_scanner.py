
import asyncio
import os
import re
import tempfile
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

from .host_discovery import run_tool, write_target_file, ToolNotAvailableError

TOP_100_PORTS = [
    80, 23, 443, 21, 22, 25, 3389, 110, 445, 139,
    143, 53, 135, 3306, 8080, 1723, 111, 995, 993, 5900,
    1025, 587, 8888, 199, 1720, 465, 548, 113, 81, 6001,
    10000, 514, 5060, 179, 1026, 2000, 8443, 8000, 32768, 1027,
    5001, 8008, 2001, 515, 8083, 1028, 9, 5666, 631, 49152,
    49154, 9200, 1029, 1720, 8081, 2049, 88, 79, 3001, 5801,
    100, 7080, 2121, 443, 2717, 4899, 8200, 7001, 9090, 5101,
    1080, 7777, 3128, 19, 6646, 646, 1433, 3986, 1434, 6667,
    1723, 116, 49155, 2107, 3513, 9999, 8291, 7070, 16992, 27017,
    3000, 6379, 5000, 8082, 8085, 9100, 4848, 2222, 5432, 11211,
]

TOP_1000_PORTS = (
    "1,3,4,6,7,9,13,17,19,20,21,22,23,24,25,26,30,32,33,37,42,43,49,53,70,"
    "79,80,81,82,83,84,85,88,89,90,99,100,106,109,110,111,113,119,125,135,139,"
    "143,144,146,161,163,179,199,211,212,222,254,255,256,259,264,280,301,306,"
    "311,340,366,389,406,407,416,417,425,427,443,444,445,458,464,465,481,497,"
    "500,512,513,514,515,524,541,543,544,545,548,554,555,563,587,593,616,617,"
    "625,631,636,646,648,666,667,668,683,687,691,700,705,711,714,720,722,726,"
    "749,765,777,783,787,800,801,808,843,873,880,888,898,900,901,902,903,911,"
    "912,981,987,990,992,993,995,999,1000,1001,1002,1007,1009,1010,1011,1021,"
    "1022,1023,1024,1025,1026,1027,1028,1029,1030,1031,1032,1033,1034,1035,"
    "1036,1037,1038,1039,1040,1041,1044,1048,1049,1050,1053,1054,1056,1058,"
    "1059,1064,1065,1066,1069,1071,1074,1080,1110,1234,1433,1494,1521,1720,"
    "1723,1755,1900,2000,2001,2002,2003,2049,2121,2181,2222,2375,2376,2379,"
    "2380,2483,2484,3000,3001,3128,3268,3269,3306,3389,3690,3872,4000,4001,"
    "4369,4848,5000,5001,5060,5432,5555,5601,5900,5984,5985,5986,6000,6001,"
    "6379,6443,7001,7080,7443,7777,8000,8001,8008,8080,8081,8082,8083,8084,"
    "8085,8086,8088,8089,8090,8091,8443,8888,8983,9000,9001,9090,9092,9200,"
    "9300,9418,9999,10000,11211,27017,27018,28017,50000,50070"
)

CRITICAL_UDP_PORTS = "53,67,68,69,123,161,162,500,514,520,1900,4500,5353"

def get_ports_spec(spec: str) -> str:
    if spec == "top100":
        return ",".join(str(p) for p in TOP_100_PORTS)
    if spec == "top1000":
        return TOP_1000_PORTS
    if spec == "all":
        return "1-65535"
    return spec

async def masscan_fast_pass(alive_ips: list[str], ports_spec: str, config: dict) -> dict[str, list[int]]:
    tool = config["tools"].get("masscan")
    if not tool:
        return {}

    target_file = await write_target_file(alive_ips)
    out_file = tempfile.mktemp(suffix=".xml")
    rate = config.get("masscan", {}).get("rate", 50000)
    iface = config.get("masscan", {}).get("interface") or ""

    cmd = [
        "sudo", tool,
        "-p", ports_spec,
        f"--rate={rate}",
        "--open-only",
        "-iL", target_file,
        "-oX", out_file,
    ]
    if iface:
        cmd += ["-e", iface]

    try:
        await run_tool(cmd, timeout=3600)
    except ToolNotAvailableError:
        return {}
    finally:
        try:
            os.unlink(target_file)
        except Exception:
            pass

    results = {}
    try:
        tree = ET.parse(out_file)
        root = tree.getroot()
        for host_el in root.findall("host"):
            addr_el = host_el.find("address[@addrtype='ipv4']")
            if addr_el is None:
                continue
            ip = addr_el.get("addr", "")
            ports = []
            for port_el in host_el.findall(".//port"):
                state_el = port_el.find("state")
                if state_el is not None and state_el.get("state") == "open":
                    ports.append(int(port_el.get("portid", 0)))
            if ports:
                results[ip] = ports
    except Exception:
        pass
    finally:
        try:
            os.unlink(out_file)
        except Exception:
            pass

    return results

async def nmap_service_scan(ips_with_ports: dict[str, list[int]], config: dict) -> dict[str, dict]:
    tool = config["tools"].get("nmap")
    if not tool:
        return {}

    items = list(ips_with_ports.items())
    chunk_size = 50
    all_results = {}

    for i in range(0, len(items), chunk_size):
        chunk = items[i:i + chunk_size]
        tasks = [_nmap_single_host(ip, ports, config, tool) for ip, ports in chunk]
        chunk_results = await asyncio.gather(*tasks, return_exceptions=True)
        for (ip, _), result in zip(chunk, chunk_results):
            if isinstance(result, dict):
                all_results[ip] = result

    return all_results

async def _nmap_single_host(ip: str, ports: list[int], config: dict, tool: str) -> dict:
    ports_str = ",".join(str(p) for p in sorted(ports))
    out_file = tempfile.mktemp(suffix=".xml")
    timing = config.get("nmap", {}).get("timing", "T4")
    scripts = config.get("nmap", {}).get("scripts_service", "banner,http-title,ssl-cert")

    cmd = [
        "sudo", tool,
        "-Pn", "-n",
        "-sV", "--version-intensity", "7",
        "-O", "--osscan-guess",
        f"--script={scripts}",
        "-p", ports_str,
        f"-{timing}",
        "--min-parallelism", "10",
        "--host-timeout", "300s",
        "-oX", out_file,
        ip,
    ]
    try:
        await run_tool(cmd, timeout=360)
    except ToolNotAvailableError:
        return {}

    result = _parse_nmap_service_xml(out_file, ip)
    try:
        os.unlink(out_file)
    except Exception:
        pass
    return result

def _parse_nmap_service_xml(xml_path: str, ip: str) -> dict:
    result = {"ports": {}, "os": {"guess": "", "accuracy": 0, "cpe": ""}, "scripts": {}}
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
    except Exception:
        return result

    host_el = root.find("host")
    if host_el is None:
        return result

    for port_el in host_el.findall(".//port"):
        state_el = port_el.find("state")
        if state_el is None or state_el.get("state") != "open":
            continue
        portid = int(port_el.get("portid", 0))
        proto = port_el.get("protocol", "tcp")
        svc_el = port_el.find("service")
        svc = {}
        if svc_el is not None:
            svc = {
                "service": svc_el.get("name", ""),
                "product": svc_el.get("product", ""),
                "version": svc_el.get("version", ""),
                "extrainfo": svc_el.get("extrainfo", ""),
                "ostype": svc_el.get("ostype", ""),
                "cpe": [c.text for c in svc_el.findall("cpe") if c.text],
                "tunnel": svc_el.get("tunnel", ""),
            }

        port_scripts = {}
        for script_el in port_el.findall("script"):
            script_id = script_el.get("id", "")
            port_scripts[script_id] = script_el.get("output", "")

        result["ports"][f"{portid}/{proto}"] = {**svc, "scripts": port_scripts}

    for osmatch_el in host_el.findall(".//osmatch"):
        accuracy = int(osmatch_el.get("accuracy", 0))
        if accuracy > result["os"]["accuracy"]:
            result["os"]["guess"] = osmatch_el.get("name", "")
            result["os"]["accuracy"] = accuracy
            cpe_el = osmatch_el.find(".//cpe")
            if cpe_el is not None and cpe_el.text:
                result["os"]["cpe"] = cpe_el.text

    for script_el in host_el.findall(".//hostscript/script"):
        script_id = script_el.get("id", "")
        result["scripts"][script_id] = script_el.get("output", "")

    return result

async def nmap_udp_scan(alive_ips: list[str], config: dict) -> dict[str, dict]:
    tool = config["tools"].get("nmap")
    if not tool:
        return {}

    target_file = await write_target_file(alive_ips)
    out_file = tempfile.mktemp(suffix=".xml")
    timing = config.get("nmap", {}).get("timing", "T4")

    cmd = [
        "sudo", tool,
        "-sU", "-Pn", "-n",
        "-p", CRITICAL_UDP_PORTS,
        "--open",
        f"-{timing}",
        "--host-timeout", "120s",
        "-iL", target_file,
        "-oX", out_file,
    ]
    try:
        await run_tool(cmd, timeout=1800)
    except ToolNotAvailableError:
        return {}
    finally:
        try:
            os.unlink(target_file)
        except Exception:
            pass

    udp_results = {}
    try:
        tree = ET.parse(out_file)
        root = tree.getroot()
        for host_el in root.findall("host"):
            addr_el = host_el.find("address[@addrtype='ipv4']")
            if addr_el is None:
                continue
            ip = addr_el.get("addr", "")
            ports = {}
            for port_el in host_el.findall(".//port[@protocol='udp']"):
                state_el = port_el.find("state")
                if state_el is None:
                    continue
                state = state_el.get("state", "")
                if state in ("open", "open|filtered"):
                    portid = int(port_el.get("portid", 0))
                    svc_el = port_el.find("service")
                    ports[portid] = {
                        "state": state,
                        "service": svc_el.get("name", "") if svc_el is not None else "",
                        "version": svc_el.get("version", "") if svc_el is not None else "",
                    }
            if ports:
                udp_results[ip] = ports
    except Exception:
        pass
    finally:
        try:
            os.unlink(out_file)
        except Exception:
            pass

    return udp_results

async def run_port_scanner(state: dict, config: dict, include_udp: bool = False,
                           ports: str = "top1000", fast_only: bool = False) -> None:
    alive_ips = [ip for ip, h in state["hosts"].items() if h.get("status") == "alive"]
    if not alive_ips:
        print("  [Phase 3] No alive hosts to scan.")
        return

    print(f"\n  [Phase 3] Port Scanning — {len(alive_ips)} alive hosts, ports: {ports}")
    ports_spec = get_ports_spec(ports)

    masscan_results = await masscan_fast_pass(alive_ips, ports_spec, config)
    print(f"  [Phase 3] masscan complete — {len(masscan_results)} hosts with open ports")

    for ip, open_ports in masscan_results.items():
        host = state["hosts"].get(ip)
        if not host:
            continue
        for port in open_ports:
            if port not in host["ports"]["tcp"]:
                host["ports"]["tcp"][port] = {"state": "open", "service": "", "version": "", "source": "masscan"}

    if fast_only:
        state["stats"]["phases_completed"].append("port_scan_fast")
        return

    hosts_to_deep_scan = {
        ip: [p for p in host["ports"]["tcp"].keys() if isinstance(p, int)]
        for ip, host in state["hosts"].items()
        if host.get("status") == "alive" and host["ports"]["tcp"]
    }

    if hosts_to_deep_scan:
        print(f"  [Phase 4] Service Detection — {len(hosts_to_deep_scan)} hosts")
        nmap_results = await nmap_service_scan(hosts_to_deep_scan, config)

        for ip, data in nmap_results.items():
            host = state["hosts"].get(ip)
            if not host:
                continue

            for port_proto, port_data in data.get("ports", {}).items():
                port_num, proto = port_proto.split("/")
                port_num = int(port_num)
                host["ports"][proto][port_num] = {
                    "state": "open",
                    "service": port_data.get("service", ""),
                    "version": f"{port_data.get('product', '')} {port_data.get('version', '')}".strip(),
                    "extrainfo": port_data.get("extrainfo", ""),
                    "cpe": port_data.get("cpe", []),
                    "scripts": port_data.get("scripts", {}),
                    "source": "nmap",
                }

            if data.get("os", {}).get("guess"):
                host["os"] = data["os"]

            host.setdefault("host_scripts", {}).update(data.get("scripts", {}))
            host["scan_timestamps"]["port_scan"] = _now()

    if include_udp:
        print(f"  [Phase 3] UDP Scan — critical ports ({CRITICAL_UDP_PORTS})")
        udp_results = await nmap_udp_scan(alive_ips, config)
        for ip, udp_ports in udp_results.items():
            host = state["hosts"].get(ip)
            if host:
                for port, port_data in udp_ports.items():
                    host["ports"]["udp"][port] = {**port_data, "source": "nmap_udp"}

    total_ports = sum(
        len(h["ports"]["tcp"]) + len(h["ports"]["udp"])
        for h in state["hosts"].values()
        if h.get("status") == "alive"
    )
    state["stats"]["open_ports_found"] = total_ports
    state["stats"]["phases_completed"].append("port_scan")
    print(f"  [Phase 3/4] Complete — {total_ports} open ports discovered")

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
