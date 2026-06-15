
import shutil
import yaml
from pathlib import Path

DEFAULT_CONFIG = {
    "scan": {
        "concurrency": 200,
        "timeout": 10,
        "max_retries": 2,
        "confidence_threshold": 0.5,
        "output_dir": "./eagleeyes_results",
    },
    "masscan": {
        "path": "masscan",
        "rate": 50000,
        "ports_fast": "1-1000",
        "interface": None,
    },
    "nmap": {
        "path": "nmap",
        "timing": "T4",
        "max_parallelism": 50,
        "scripts_discovery": "nbstat,smb-os-discovery,ssh-hostkey",
        "scripts_service": "banner,http-title,ssl-cert",
    },
    "arp_scan": {"path": "arp-scan", "interface": None},
    "apis": {
        "shodan": {
            "key": None,
            "internetdb_url": "https://internetdb.shodan.io",
            "api_url": "https://api.shodan.io",
            "rate_limit": 1,
        },
        "censys": {"api_id": None, "api_secret": None, "rate_limit": 0.4},
        "ipinfo": {"token": None, "url": "https://ipinfo.io", "rate_limit": 2},
        "crt_sh": {"url": "https://crt.sh", "rate_limit": 2},
        "bgp": {"url": "https://api.bgpview.io", "rate_limit": 2},
    },
    "output": {"color": True, "verbose": False, "formats": ["txt", "json", "csv", "html"]},
    "rate_limits": {"dns_concurrent": 100, "http_concurrent": 50, "ssl_concurrent": 50},
    "tools": {},
}

def _deep_merge(base: dict, override: dict) -> dict:
    result = base.copy()
    for k, v in override.items():
        if k in result and isinstance(result[k], dict) and isinstance(v, dict):
            result[k] = _deep_merge(result[k], v)
        else:
            result[k] = v
    return result

def load_config(config_path: str = "config.yml", cli_overrides: dict | None = None) -> dict:
    config = DEFAULT_CONFIG.copy()
    path = Path(config_path)
    if path.exists():
        with open(path, "r") as f:
            file_cfg = yaml.safe_load(f) or {}
        config = _deep_merge(config, file_cfg)
    if cli_overrides:
        config = _deep_merge(config, cli_overrides)
    config["tools"] = detect_tools(config)
    return config

def detect_tools(config: dict) -> dict[str, str | None]:
    tools = {}
    for name, cfg_key in [("masscan", "masscan"), ("nmap", "nmap"), ("arp-scan", "arp_scan")]:
        configured_path = config.get(cfg_key, {}).get("path", name) if cfg_key != "arp-scan" else config.get("arp_scan", {}).get("path", "arp-scan")
        found = shutil.which(configured_path) or shutil.which(name)
        tools[name] = found
    return tools

def validate_config(config: dict) -> list[str]:
    warnings = []
    if not config["tools"].get("nmap"):
        warnings.append("nmap not found — port scanning and service detection unavailable")
    if not config["tools"].get("masscan"):
        warnings.append("masscan not found — host discovery will use nmap only (slower for large subnets)")
    if not config["tools"].get("arp-scan"):
        warnings.append("arp-scan not found — ARP discovery unavailable (local networks may be less accurate)")
    if not config["apis"]["shodan"].get("key"):
        warnings.append("No Shodan API key — using free InternetDB only (limited data)")
    if not config["apis"]["censys"].get("api_id"):
        warnings.append("No Censys credentials — Censys lookups disabled")
    return warnings

def get_api_status(config: dict) -> dict[str, str]:
    return {
        "shodan_internetdb": "free",
        "shodan_api": "paid" if config["apis"]["shodan"].get("key") else "unavailable",
        "censys": "paid" if config["apis"]["censys"].get("api_id") else "unavailable",
        "ipinfo": "free_token" if config["apis"]["ipinfo"].get("token") else "free_limited",
        "bgpview": "free",
        "crt_sh": "free",
    }
