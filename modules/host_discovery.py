
import asyncio
import ipaddress
import os
import re
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

from .input_parser import TargetSet, is_rfc1918
from .passive_recon import _empty_host

METHOD_WEIGHTS = {
    "arp": 1.0,
    "icmp_echo": 0.6,
    "icmp_timestamp": 0.5,
    "tcp_syn_ack": 0.5,
    "tcp_reset": 0.4,
    "udp_response": 0.3,
    "passive_hint": 0.4,
}

def calculate_confidence(methods: set[str]) -> float:
    if "arp" in methods:
        return 1.0
    score = sum(METHOD_WEIGHTS.get(m, 0.3) for m in methods)
    return min(round(score, 2), 1.0)

class ToolNotAvailableError(Exception):
    pass

async def run_tool(cmd: list[str], timeout: int = 300) -> tuple[str, str, int]:
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return stdout.decode(errors="ignore"), stderr.decode(errors="ignore"), proc.returncode
    except asyncio.TimeoutError:
        try:
            proc.kill()
        except Exception:
            pass
        return "", "timeout", -1
    except FileNotFoundError:
        raise ToolNotAvailableError(f"Tool not found: {cmd[0]}")

async def write_target_file(ips: list[str], suffix: str = ".txt") -> str:
    fd, path = tempfile.mkstemp(suffix=suffix)
    with os.fdopen(fd, "w") as f:
        f.write("\n".join(ips) + "\n")
    return path

async def arp_scan_local(target: str, config: dict) -> dict[str, set[str]]:
    tool = config["tools"].get("arp-scan")
    if not tool:
        return {}
    iface = config.get("arp_scan", {}).get("interface") or ""
    cmd = [tool]
    if iface:
        cmd += ["--interface", iface]
    cmd.append(target)

    try:
        stdout, _, rc = await run_tool(["sudo"] + cmd, timeout=60)
    except ToolNotAvailableError:
        return {}

    results = {}
    for line in stdout.splitlines():
        m = re.match(r"^(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f:]{17})", line, re.IGNORECASE)
        if m:
            ip = m.group(1)
            results[ip] = {"arp"}
    return results

async def nmap_ping_sweep(targets: list[str], config: dict) -> dict[str, set[str]]:
    tool = config["tools"].get("nmap")
    if not tool:
        return {}

    target_file = await write_target_file(targets)
    out_file = tempfile.mktemp(suffix=".xml")

    timing = config.get("nmap", {}).get("timing", "T4")
    cmd = [
        "sudo", tool,
        "-sn", "-n", "--reason",
        "-PE", "-PP",
        "-PS22,80,443,8080,3389",
        "-PA80,443",
        "-PU53",
        f"-{timing}",
        "--min-parallelism", "50",
        "--max-parallelism", str(config.get("nmap", {}).get("max_parallelism", 50)),
        "-iL", target_file,
        "-oX", out_file,
    ]
    try:
        await run_tool(cmd, timeout=600)
    except ToolNotAvailableError:
        return {}
    finally:
        try:
            os.unlink(target_file)
        except Exception:
            pass

    results = _parse_nmap_ping_xml(out_file)
    try:
        os.unlink(out_file)
    except Exception:
        pass
    return results

def _parse_nmap_ping_xml(xml_path: str) -> dict[str, set[str]]:
    results = {}
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
    except Exception:
        return results

    for host_el in root.findall("host"):
        status_el = host_el.find("status")
        if status_el is None or status_el.get("state") != "up":
            continue

        addr_el = host_el.find("address[@addrtype='ipv4']")
        if addr_el is None:
            continue
        ip = addr_el.get("addr", "")
        if not ip:
            continue

        methods = set()
        reason = status_el.get("reason", "")
        if "echo-reply" in reason:
            methods.add("icmp_echo")
        elif "timestamp-reply" in reason:
            methods.add("icmp_timestamp")
        elif "syn-ack" in reason:
            methods.add("tcp_syn_ack")
        elif "reset" in reason:
            methods.add("tcp_reset")
        elif "udp" in reason:
            methods.add("udp_response")
        else:
            methods.add("tcp_syn_ack")

        results[ip] = methods
    return results

async def masscan_sweep(targets: TargetSet, config: dict, ports: str = "80,443,22,8080") -> dict[str, set[str]]:
    tool = config["tools"].get("masscan")
    if not tool:
        return {}

    rate = config.get("masscan", {}).get("rate", 50000)
    out_file = tempfile.mktemp(suffix=".xml")
    iface = config.get("masscan", {}).get("interface") or ""

    if targets.cidrs:
        target_args = targets.cidrs
    else:
        target_file = await write_target_file(targets.ip_list())
        target_args = ["-iL", target_file]

    cmd = [
        "sudo", tool,
        f"--rate={rate}",
        "-p", ports,
        "--ping",
        "--open-only",
        "-oX", out_file,
        "--status-every", "10s",
    ]
    if iface:
        cmd += ["-e", iface]
    cmd += (target_args if targets.cidrs else target_args)

    try:
        await run_tool(cmd, timeout=7200)
    except ToolNotAvailableError:
        return {}
    finally:
        if not targets.cidrs:
            try:
                os.unlink(target_file)
            except Exception:
                pass

    results = _parse_masscan_xml(out_file)
    try:
        os.unlink(out_file)
    except Exception:
        pass
    return results

def _parse_masscan_xml(xml_path: str) -> dict[str, set[str]]:
    results = {}
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
    except Exception:
        return results

    for host_el in root.findall("host"):
        addr_el = host_el.find("address[@addrtype='ipv4']")
        if addr_el is None:
            continue
        ip = addr_el.get("addr", "")
        if not ip:
            continue

        methods = results.setdefault(ip, set())
        for port_el in host_el.findall(".//port"):
            state_el = port_el.find("state")
            if state_el is not None and state_el.get("state") == "open":
                portid = port_el.get("portid", "")
                proto = port_el.get("protocol", "tcp")
                if proto == "icmp":
                    methods.add("icmp_echo")
                else:
                    methods.add("tcp_syn_ack")
    return results

async def run_host_discovery(state: dict, config: dict, targets: TargetSet) -> None:
    threshold = config["scan"]["confidence_threshold"]
    total = targets.estimated_count

    passive_ips = {ip for ip, h in state["hosts"].items() if h.get("passive", {}).get("internetdb")}

    print(f"\n  [Phase 2] Host Discovery — {total:,} targets, strategy: ", end="")

    combined: dict[str, set[str]] = {}

    if targets.network_type == "local" and total <= 256:

        print("ARP + nmap (local)")
        target_str = targets.cidrs[0] if targets.cidrs else " ".join(targets.ip_list())
        arp_results = await arp_scan_local(target_str, config)
        combined.update(arp_results)
        nmap_results = await nmap_ping_sweep(targets.ip_list(), config)
        for ip, methods in nmap_results.items():
            combined.setdefault(ip, set()).update(methods)

    elif total <= 256:

        print("nmap multi-probe")
        nmap_results = await nmap_ping_sweep(targets.ip_list(), config)
        combined.update(nmap_results)

    elif total <= 65536:

        print("masscan sweep + nmap verify")
        masscan_results = await masscan_sweep(targets, config)
        combined.update(masscan_results)

        uncertain = [ip for ip, methods in combined.items()
                     if calculate_confidence(methods) < 0.7]
        if uncertain:
            nmap_verify = await nmap_ping_sweep(uncertain[:2000], config)
            for ip, methods in nmap_verify.items():
                combined.setdefault(ip, set()).update(methods)

    else:

        print("masscan only (large subnet)")
        masscan_results = await masscan_sweep(targets, config)
        combined.update(masscan_results)

    for ip in passive_ips:
        if ip not in combined:
            combined[ip] = {"passive_hint"}

    alive_count = 0
    for ip, methods in combined.items():
        conf = calculate_confidence(methods)
        if ip not in state["hosts"]:
            state["hosts"][ip] = _empty_host(ip)

        host = state["hosts"][ip]
        if conf >= threshold:
            host["status"] = "alive"
            alive_count += 1
        else:
            host["status"] = "uncertain"

        host["confidence"] = conf
        host["discovery_methods"] = sorted(methods)
        host["scan_timestamps"]["host_discovery"] = _now()

    if total <= 65536:
        for ip in targets.ip_list():
            if ip not in state["hosts"]:
                h = _empty_host(ip)
                h["status"] = "dead"
                state["hosts"][ip] = h

    state["stats"]["alive_hosts"] = alive_count
    print(f"  [Phase 2] Complete — {alive_count:,} alive hosts found")

def _now() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()
