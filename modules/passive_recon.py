
import asyncio
import json
import re
import time
from base64 import b64encode
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

class RateLimiter:

    def __init__(self, rate_per_second: float):
        self._interval = 1.0 / max(rate_per_second, 0.01)
        self._lock = asyncio.Lock()
        self._last = 0.0

    async def acquire(self) -> None:
        async with self._lock:
            now = time.monotonic()
            wait = self._interval - (now - self._last)
            if wait > 0:
                await asyncio.sleep(wait)
            self._last = time.monotonic()

async def _get_json(url: str, headers: dict | None = None, timeout: int = 10) -> dict | list | None:
    loop = asyncio.get_event_loop()
    hdrs = {"User-Agent": "eagleEyes/5.0", **(headers or {})}

    def fetch():
        try:
            req = Request(url, headers=hdrs)
            with urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode())
        except HTTPError as e:
            if e.code == 404:
                return None
            raise
        except (URLError, Exception):
            return None

    try:
        return await asyncio.wait_for(loop.run_in_executor(None, fetch), timeout=timeout + 2)
    except asyncio.TimeoutError:
        return None
    except Exception:
        return None

_internetdb_limiter = None

def _get_internetdb_limiter(config: dict) -> RateLimiter:
    global _internetdb_limiter
    if _internetdb_limiter is None:
        rate = config.get("apis", {}).get("shodan", {}).get("rate_limit", 1)
        _internetdb_limiter = RateLimiter(rate)
    return _internetdb_limiter

async def query_internetdb(ip: str, config: dict) -> dict:
    limiter = _get_internetdb_limiter(config)
    await limiter.acquire()
    base = config.get("apis", {}).get("shodan", {}).get("internetdb_url", "https://internetdb.shodan.io")
    data = await _get_json(f"{base}/{ip}")
    if not data or not isinstance(data, dict):
        return {}
    return {
        "ports": data.get("ports", []),
        "hostnames": data.get("hostnames", []),
        "tags": data.get("tags", []),
        "cpes": data.get("cpes", []),
        "vulns": data.get("vulns", []),
    }

_shodan_api_limiter = None

def _get_shodan_limiter(config: dict) -> RateLimiter:
    global _shodan_api_limiter
    if _shodan_api_limiter is None:
        _shodan_api_limiter = RateLimiter(1)
    return _shodan_api_limiter

async def query_shodan_api(ip: str, config: dict) -> dict:
    key = config.get("apis", {}).get("shodan", {}).get("key")
    if not key:
        return {}
    limiter = _get_shodan_limiter(config)
    await limiter.acquire()
    base = config.get("apis", {}).get("shodan", {}).get("api_url", "https://api.shodan.io")
    data = await _get_json(f"{base}/shodan/host/{ip}?key={key}")
    if not data or not isinstance(data, dict):
        return {}
    ports = []
    banners = {}
    for item in data.get("data", []):
        port = item.get("port")
        if port:
            ports.append(port)
            banners[port] = {
                "transport": item.get("transport", "tcp"),
                "service": item.get("_shodan", {}).get("module", ""),
                "banner": item.get("data", "").strip()[:500],
                "version": item.get("version", ""),
                "product": item.get("product", ""),
            }
    return {
        "ports": ports,
        "banners": banners,
        "hostnames": data.get("hostnames", []),
        "domains": data.get("domains", []),
        "os": data.get("os"),
        "org": data.get("org"),
        "isp": data.get("isp"),
        "asn": data.get("asn"),
        "country_code": data.get("country_code"),
        "city": data.get("city"),
        "vulns": list(data.get("vulns", {}).keys()),
        "tags": data.get("tags", []),
        "last_update": data.get("last_update"),
    }

_bgp_limiter = None

def _get_bgp_limiter(config: dict) -> RateLimiter:
    global _bgp_limiter
    if _bgp_limiter is None:
        rate = config.get("apis", {}).get("bgp", {}).get("rate_limit", 2)
        _bgp_limiter = RateLimiter(rate)
    return _bgp_limiter

async def query_bgpview(ip_or_cidr: str, config: dict) -> dict:
    limiter = _get_bgp_limiter(config)
    await limiter.acquire()
    base = config.get("apis", {}).get("bgp", {}).get("url", "https://api.bgpview.io")
    endpoint = "ip" if "/" not in ip_or_cidr else "prefix"
    target = ip_or_cidr.replace("/", "%2F") if "/" in ip_or_cidr else ip_or_cidr
    data = await _get_json(f"{base}/{endpoint}/{target}")
    if not data or not isinstance(data, dict):
        return {}
    inner = data.get("data", {})
    prefixes = inner.get("prefixes", [])
    if not prefixes:
        return {}
    first = prefixes[0]
    asn_info = first.get("asn", {})
    return {
        "asn": f"AS{asn_info.get('asn', '')}",
        "asn_name": asn_info.get("name", ""),
        "asn_description": asn_info.get("description", ""),
        "prefix": first.get("prefix", ""),
        "country_code": first.get("country_code", ""),
        "is_cdn": _detect_cdn(asn_info.get("description", "")),
    }

def _detect_cdn(description: str) -> bool:
    cdn_keywords = ["cloudflare", "akamai", "fastly", "amazon", "aws",
                    "google", "microsoft", "azure", "cdn", "incapsula",
                    "imperva", "sucuri", "maxcdn"]
    desc_lower = description.lower()
    return any(k in desc_lower for k in cdn_keywords)

_ipinfo_limiter = None

def _get_ipinfo_limiter(config: dict) -> RateLimiter:
    global _ipinfo_limiter
    if _ipinfo_limiter is None:
        rate = config.get("apis", {}).get("ipinfo", {}).get("rate_limit", 2)
        _ipinfo_limiter = RateLimiter(rate)
    return _ipinfo_limiter

async def query_ipinfo(ip: str, config: dict) -> dict:
    limiter = _get_ipinfo_limiter(config)
    await limiter.acquire()
    token = config.get("apis", {}).get("ipinfo", {}).get("token")
    base = config.get("apis", {}).get("ipinfo", {}).get("url", "https://ipinfo.io")
    url = f"{base}/{ip}/json"
    if token:
        url += f"?token={token}"
    data = await _get_json(url)
    if not data or not isinstance(data, dict):
        return {}
    org = data.get("org", "")
    asn_match = re.match(r"(AS\d+)\s+(.*)", org)
    return {
        "asn": asn_match.group(1) if asn_match else "",
        "org": asn_match.group(2) if asn_match else org,
        "city": data.get("city", ""),
        "region": data.get("region", ""),
        "country": data.get("country", ""),
        "timezone": data.get("timezone", ""),
        "hostname": data.get("hostname", ""),
    }

_censys_limiter = None

def _get_censys_limiter(config: dict) -> RateLimiter:
    global _censys_limiter
    if _censys_limiter is None:
        rate = config.get("apis", {}).get("censys", {}).get("rate_limit", 0.4)
        _censys_limiter = RateLimiter(rate)
    return _censys_limiter

async def query_censys(ip: str, config: dict) -> dict:
    api_id = config.get("apis", {}).get("censys", {}).get("api_id")
    api_secret = config.get("apis", {}).get("censys", {}).get("api_secret")
    if not api_id or not api_secret:
        return {}
    limiter = _get_censys_limiter(config)
    await limiter.acquire()
    creds = b64encode(f"{api_id}:{api_secret}".encode()).decode()
    headers = {"Authorization": f"Basic {creds}"}
    data = await _get_json(
        f"https://search.censys.io/api/v2/hosts/{ip}",
        headers=headers,
    )
    if not data or not isinstance(data, dict):
        return {}
    result = data.get("result", {})
    services = result.get("services", [])
    ports = []
    service_map = {}
    for svc in services:
        port = svc.get("port")
        if port:
            ports.append(port)
            service_map[port] = {
                "service_name": svc.get("service_name", ""),
                "transport_protocol": svc.get("transport_protocol", "tcp"),
                "banner": svc.get("banner", "")[:300] if svc.get("banner") else "",
            }
    return {
        "ports": ports,
        "services": service_map,
        "os": result.get("os", {}).get("product", ""),
        "last_updated": result.get("last_updated_at", ""),
    }

_crtsh_limiter = None

def _get_crtsh_limiter(config: dict) -> RateLimiter:
    global _crtsh_limiter
    if _crtsh_limiter is None:
        rate = config.get("apis", {}).get("crt_sh", {}).get("rate_limit", 2)
        _crtsh_limiter = RateLimiter(rate)
    return _crtsh_limiter

async def query_crt_sh(domain: str, config: dict) -> list[str]:
    limiter = _get_crtsh_limiter(config)
    await limiter.acquire()
    base = config.get("apis", {}).get("crt_sh", {}).get("url", "https://crt.sh")
    data = await _get_json(f"{base}/?q=%.{domain}&output=json")
    if not data or not isinstance(data, list):
        return []
    found = set()
    for entry in data:
        name_value = entry.get("name_value", "")
        for sub in name_value.splitlines():
            sub = sub.strip().lstrip("*.")
            if sub.endswith(domain) and sub:
                found.add(sub.lower())
    return sorted(found)

def merge_passive_to_host(ip: str, results: dict, state: dict) -> None:
    if ip not in state["hosts"]:
        state["hosts"][ip] = _empty_host(ip)

    host = state["hosts"][ip]
    host["passive"].update(results)

    for source in ("internetdb", "shodan_api", "censys"):
        src_data = results.get(source, {})
        for port in src_data.get("ports", []):
            proto = "tcp"
            if source == "censys":
                proto = src_data.get("services", {}).get(port, {}).get("transport_protocol", "tcp")
            if port not in host["ports"][proto]:
                host["ports"][proto][port] = {"state": "passive-hint", "service": "", "version": ""}

    for source in ("internetdb", "shodan_api"):
        for hostname in results.get(source, {}).get("hostnames", []):
            if hostname not in host["domains"]["passive_api"]:
                host["domains"]["passive_api"].append(hostname)

    if results.get("ipinfo"):
        d = results["ipinfo"]
        host["asn"] = {
            "number": d.get("asn", ""),
            "org": d.get("org", ""),
            "country": d.get("country", ""),
            "city": d.get("city", ""),
            "region": d.get("region", ""),
        }
    if results.get("bgp"):
        d = results["bgp"]
        if not host["asn"]["number"]:
            host["asn"]["number"] = d.get("asn", "")
            host["asn"]["org"] = d.get("asn_description", "")
            host["asn"]["country"] = d.get("country_code", "")
        host["asn"]["prefix"] = d.get("prefix", "")
        host["asn"]["is_cdn"] = d.get("is_cdn", False)

    for source in ("internetdb", "shodan_api"):
        for cve in results.get(source, {}).get("vulns", []):
            entry = {"cve_id": cve, "source": "passive"}
            if entry not in host["vulns"]:
                host["vulns"].append(entry)

def _empty_host(ip: str) -> dict:
    return {
        "ip": ip,
        "status": "unknown",
        "confidence": 0.0,
        "discovery_methods": [],
        "asn": {"number": "", "org": "", "country": "", "city": "", "region": "", "prefix": "", "is_cdn": False},
        "passive": {},
        "ports": {"tcp": {}, "udp": {}},
        "os": {"guess": "", "accuracy": 0, "cpe": ""},
        "domains": {"ptr": [], "ssl_cn": [], "ssl_sans": [], "http_headers": [], "crt_sh": [], "passive_api": [], "all": []},
        "services": {},
        "vulns": [],
        "raw_nmap_xml": "",
        "scan_timestamps": {},
    }

async def run_passive_recon(state: dict, config: dict, ips: list[str] | None = None) -> None:
    targets = ips or list(state.get("targets_sample", []))
    if not targets:
        return

    cidrs = state["meta"].get("target_cidrs", [])
    if cidrs:
        bgp_tasks = [query_bgpview(cidr, config) for cidr in cidrs]
        bgp_results = await asyncio.gather(*bgp_tasks, return_exceptions=True)
        for cidr, result in zip(cidrs, bgp_results):
            if isinstance(result, dict) and result:
                state.setdefault("bgp_prefixes", {})[cidr] = result
                if result.get("is_cdn"):
                    print(f"  [!] CDN/Cloud detected for {cidr}: {result.get('asn_description')} — you may be scanning edge nodes, not origin")

    sem = asyncio.Semaphore(config["scan"]["concurrency"])

    async def probe_one(ip: str) -> None:
        async with sem:
            results = {}
            tasks = {
                "internetdb": query_internetdb(ip, config),
                "ipinfo": query_ipinfo(ip, config),
            }
            if config["apis"]["shodan"].get("key"):
                tasks["shodan_api"] = query_shodan_api(ip, config)
            if config["apis"]["censys"].get("api_id"):
                tasks["censys"] = query_censys(ip, config)

            gathered = await asyncio.gather(*tasks.values(), return_exceptions=True)
            for key, res in zip(tasks.keys(), gathered):
                if isinstance(res, dict):
                    results[key] = res
                else:
                    results[key] = {}

            merge_passive_to_host(ip, results, state)

    await asyncio.gather(*[probe_one(ip) for ip in targets])

    all_hostnames = set()
    for ip in targets:
        host = state["hosts"].get(ip, {})
        all_hostnames.update(host.get("domains", {}).get("passive_api", []))

    if all_hostnames:
        crt_tasks = [query_crt_sh(h, config) for h in all_hostnames if "." in h]
        crt_results = await asyncio.gather(*crt_tasks, return_exceptions=True)
        for hostname, subs in zip(all_hostnames, crt_results):
            if isinstance(subs, list):
                state.setdefault("crt_sh_domains", {}).setdefault(hostname, []).extend(subs)
