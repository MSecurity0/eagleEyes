
import argparse
import asyncio
import json
import os
import signal
import sys
from datetime import datetime, timezone
from pathlib import Path

from modules.config import load_config, validate_config, get_api_status, detect_tools
from modules.input_parser import parse_targets
from modules.passive_recon import run_passive_recon
from modules.host_discovery import run_host_discovery
from modules.port_scanner import run_port_scanner
from modules.domain_extractor import run_domain_extractor
from modules.output import (
    print_banner, print_scan_config, print_alive_hosts_detail,
    print_final_summary, output_all
)

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="eagle_scan.py",
        description="EagleEyes v5 — Pentest Host Discovery Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="",
    )

    p.add_argument("targets", nargs="+", help="CIDR, IP, IP range, domain, or @file")

    g = p.add_argument_group("Scan Control")
    g.add_argument("--phase", metavar="PHASE",
                   help="Run only these phases (comma-separated): passive,discovery,ports,domains,output")
    g.add_argument("--skip-phase", metavar="PHASE",
                   help="Skip specific phase(s) (comma-separated)")
    g.add_argument("--resume", metavar="FILE",
                   help="Resume from a checkpoint.json file")
    g.add_argument("--config", default="config.yml", metavar="FILE",
                   help="Config file path [default: config.yml]")

    g2 = p.add_argument_group("Discovery")
    g2.add_argument("--no-passive", action="store_true",
                    help="Skip Phase 1 (passive recon)")
    g2.add_argument("--arp", action="store_true",
                    help="Force ARP scan (auto on local /24 or smaller)")
    g2.add_argument("--ping-only", action="store_true",
                    help="Stop after host discovery — no port scan")
    g2.add_argument("--confidence", type=float, default=None, metavar="FLOAT",
                    help="Min confidence to mark host alive [0.0-1.0, default: 0.5]")

    g3 = p.add_argument_group("Port Scanning")
    g3.add_argument("--ports", default="top1000", metavar="PORTS",
                    help="Port spec: top100, top1000, all, or '80,443,8080' [default: top1000]")
    g3.add_argument("--udp", action="store_true",
                    help="Include UDP scan on critical ports (53,161,123,500,...)")
    g3.add_argument("--fast-only", action="store_true",
                    help="masscan fast pass only — skip nmap deep service scan")
    g3.add_argument("--rate", type=int, default=None, metavar="INT",
                    help="masscan packets/sec [default: from config.yml]")

    g4 = p.add_argument_group("Output")
    g4.add_argument("--output", default=None, metavar="DIR",
                    help="Output directory [default: ./eagleeyes_results/]")
    g4.add_argument("--format", default=None, metavar="FMT",
                    help="Output formats: txt,json,csv,html (comma-separated) [default: all]")
    g4.add_argument("--no-color", action="store_true",
                    help="Disable ANSI color output")
    g4.add_argument("--quiet", action="store_true",
                    help="Suppress terminal output (still writes files)")
    g4.add_argument("--verbose", action="store_true",
                    help="Show per-IP debug output")

    g5 = p.add_argument_group("API Keys (override config.yml)")
    g5.add_argument("--shodan-key", metavar="KEY", help="Shodan API key")
    g5.add_argument("--censys-id", metavar="ID", help="Censys API ID")
    g5.add_argument("--censys-secret", metavar="SECRET", help="Censys API secret")
    g5.add_argument("--ipinfo-key", metavar="KEY", help="ipinfo.io token")

    g6 = p.add_argument_group("Performance")
    g6.add_argument("--concurrency", type=int, default=None, metavar="INT",
                    help="Max concurrent async tasks")
    g6.add_argument("--timeout", type=int, default=None, metavar="INT",
                    help="Per-host timeout in seconds")

    return p

def build_scan_id() -> str:
    return f"eagleeyes-{datetime.now().strftime('%Y%m%d-%H%M%S')}"

def new_state(targets_summary: str, phases: list[str], cidrs: list[str]) -> dict:
    return {
        "meta": {
            "scan_id": build_scan_id(),
            "start_time": datetime.now(timezone.utc).isoformat(),
            "end_time": None,
            "target_input": targets_summary,
            "target_cidrs": cidrs,
            "phases": phases,
        },
        "targets_sample": [],
        "hosts": {},
        "bgp_prefixes": {},
        "crt_sh_domains": {},
        "stats": {
            "total_targets": 0,
            "alive_hosts": 0,
            "open_ports_found": 0,
            "domains_extracted": 0,
            "phases_completed": [],
        },
        "errors": [],
    }

async def save_checkpoint(state: dict, config: dict) -> None:
    scan_id = state["meta"]["scan_id"]
    out_dir = Path(config["scan"]["output_dir"]) / scan_id
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "checkpoint.json"
    path.write_text(json.dumps(state, indent=2, default=str), encoding="utf-8")

def load_checkpoint(filepath: str) -> dict:
    return json.loads(Path(filepath).read_text(encoding="utf-8"))

async def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    cli_overrides: dict = {}
    if args.confidence is not None:
        cli_overrides.setdefault("scan", {})["confidence_threshold"] = args.confidence
    if args.rate is not None:
        cli_overrides.setdefault("masscan", {})["rate"] = args.rate
    if args.concurrency is not None:
        cli_overrides.setdefault("scan", {})["concurrency"] = args.concurrency
    if args.timeout is not None:
        cli_overrides.setdefault("scan", {})["timeout"] = args.timeout
    if args.output is not None:
        cli_overrides.setdefault("scan", {})["output_dir"] = args.output
    if args.format is not None:
        cli_overrides.setdefault("output", {})["formats"] = args.format.split(",")
    if args.shodan_key:
        cli_overrides.setdefault("apis", {}).setdefault("shodan", {})["key"] = args.shodan_key
    if args.censys_id:
        cli_overrides.setdefault("apis", {}).setdefault("censys", {})["api_id"] = args.censys_id
    if args.censys_secret:
        cli_overrides.setdefault("apis", {}).setdefault("censys", {})["api_secret"] = args.censys_secret
    if args.ipinfo_key:
        cli_overrides.setdefault("apis", {}).setdefault("ipinfo", {})["token"] = args.ipinfo_key
    if args.no_color:
        cli_overrides.setdefault("output", {})["color"] = False

    config = load_config(args.config, cli_overrides)
    warnings = validate_config(config)
    api_status = get_api_status(config)

    if not args.quiet:
        print_banner()

    all_phases = ["passive", "discovery", "ports", "domains", "output"]
    if args.phase:
        phases_to_run = [p.strip() for p in args.phase.split(",")]
    else:
        phases_to_run = list(all_phases)
    if args.no_passive:
        phases_to_run = [p for p in phases_to_run if p != "passive"]
    if args.ping_only:
        phases_to_run = [p for p in phases_to_run if p in ("passive", "discovery", "output")]

    skip_phases: set[str] = set()
    if args.skip_phase:
        skip_phases = {p.strip() for p in args.skip_phase.split(",")}

    if args.resume:
        state = load_checkpoint(args.resume)
        print(f"  [->] Resuming scan {state['meta']['scan_id']}")
        completed = set(state["stats"]["phases_completed"])
        skip_phases.update(completed)
        target_set = None
    else:

        target_set = await parse_targets(args.targets)
        if target_set.estimated_count == 0:
            print("  [!] No valid targets found. Exiting.")
            sys.exit(1)

        state = new_state(target_set.summary(), phases_to_run, target_set.cidrs)
        state["stats"]["total_targets"] = target_set.estimated_count

        if target_set.is_large():
            gen = target_set.ip_generator()
            state["targets_sample"] = [next(gen) for _ in range(min(500, target_set.estimated_count))]
        else:
            state["targets_sample"] = target_set.ip_list()

    if not args.quiet:
        print_scan_config(state, api_status, config["tools"], warnings)

    loop = asyncio.get_event_loop()

    def handle_sigint():
        print("\n\n  [!] Interrupted — saving checkpoint...")
        loop.create_task(save_checkpoint(state, config))
        sys.exit(130)

    loop.add_signal_handler(signal.SIGINT, handle_sigint)

    if "passive" in phases_to_run and "passive" not in skip_phases:
        print("\n  [Phase 1] Passive Recon (no packets sent to target)...")
        await run_passive_recon(state, config)
        await save_checkpoint(state, config)

    if "discovery" in phases_to_run and "discovery" not in skip_phases:
        if target_set is None:
            target_set = await parse_targets(args.targets)
        await run_host_discovery(state, config, target_set)
        await save_checkpoint(state, config)

        if "passive" in phases_to_run and not args.no_passive:
            alive_ips = [ip for ip, h in state["hosts"].items() if h.get("status") == "alive"]
            if alive_ips and state["stats"]["total_targets"] > 256:
                print(f"\n  [Phase 1b] Passive Recon on {len(alive_ips)} alive hosts...")
                await run_passive_recon(state, config, ips=alive_ips)
                await save_checkpoint(state, config)

    if "ports" in phases_to_run and "ports" not in skip_phases:
        await run_port_scanner(
            state, config,
            include_udp=args.udp,
            ports=args.ports,
            fast_only=args.fast_only,
        )
        await save_checkpoint(state, config)

    if "domains" in phases_to_run and "domains" not in skip_phases:
        await run_domain_extractor(state, config)
        await save_checkpoint(state, config)

    state["meta"]["end_time"] = datetime.now(timezone.utc).isoformat()

    if not args.quiet:
        print_alive_hosts_detail(state)
        print_final_summary(state)

    print("\n  Results saved to:")
    output_all(state, config)
    print()

if __name__ == "__main__":
    asyncio.run(main())
