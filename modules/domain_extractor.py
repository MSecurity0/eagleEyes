
import asyncio
import json
import re
import socket
import ssl
import os
import tempfile
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from urllib.request import Request, urlopen
from urllib.error import URLError

from .host_discovery import run_tool, write_target_file, ToolNotAvailableError
from .passive_recon import query_crt_sh, RateLimiter

TLS_PORTS = {443, 8443, 993, 465, 995, 8080, 8888, 5001, 10443}

HTTP_PORTS = {80, 8080, 8000, 8008, 8888, 81, 8081, 8082, 3000, 5000}

async def reverse_dns_bulk(ips: list[str], config: dict) -> dict[str, list[str]]:
    concurrency = config.get("rate_limits", {}).get("dns_concurrent", 100)
    sem = asyncio.Semaphore(concurrency)
    results = {}

    async def lookup(ip: str) -> None:
        async with sem:
            try:
                loop = asyncio.get_event_loop()
                hostname, _, _ = await asyncio.wait_for(
                    loop.run_in_executor(None, socket.gethostbyaddr, ip),
                    timeout=5,
                )
                results[ip] = [hostname.lower()]
            except (socket.herror, socket.gaierror, asyncio.TimeoutError, OSError):
                results[ip] = []

    await asyncio.gather(*[lookup(ip) for ip in ips])
    return results

async def extract_ssl_domains(ip: str, port: int, config: dict) -> dict:
    timeout = config.get("scan", {}).get("timeout", 10)
    loop = asyncio.get_event_loop()

    def fetch():
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((ip, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=None) as ssock:
                    cert = ssock.getpeercert()
                    der = ssock.getpeercert(binary_form=True)
                    return cert, ssock.version()
        except Exception:
            return None, None

    try:
        cert, tls_version = await asyncio.wait_for(
            loop.run_in_executor(None, fetch), timeout=timeout + 2
        )
    except asyncio.TimeoutError:
        return {}

    if not cert:
        return {}

    cn = ""
    subject = dict(x[0] for x in cert.get("subject", []))
    cn = subject.get("commonName", "")

    sans = []
    for san_type, san_value in cert.get("subjectAltName", []):
        if san_type == "DNS":
            san_value = san_value.lstrip("*.")
            if san_value:
                sans.append(san_value.lower())

    issuer = dict(x[0] for x in cert.get("issuer", []))

    return {
        "cn": cn.lower() if cn else "",
        "sans": list(set(sans)),
        "issuer": issuer.get("organizationName", issuer.get("commonName", "")),
        "not_after": cert.get("notAfter", ""),
        "not_before": cert.get("notBefore", ""),
        "tls_version": tls_version or "",
        "self_signed": issuer == subject,
    }

async def extract_ssl_all_ports(ip: str, open_ports: set[int], config: dict) -> dict[int, dict]:
    results = {}
    tls_candidates = open_ports & TLS_PORTS

    tls_candidates.update(p for p in open_ports if p in (443, 8443))

    concurrency = config.get("rate_limits", {}).get("ssl_concurrent", 50)
    sem = asyncio.Semaphore(concurrency)

    async def try_port(port: int) -> None:
        async with sem:
            result = await extract_ssl_domains(ip, port, config)
            if result:
                results[port] = result

    await asyncio.gather(*[try_port(p) for p in tls_candidates])
    return results

async def extract_http_domains(ip: str, port: int, config: dict) -> list[str]:
    timeout = config.get("scan", {}).get("timeout", 10)
    loop = asyncio.get_event_loop()
    found = []

    scheme = "https" if port in TLS_PORTS else "http"

    def fetch():
        import urllib.request
        import urllib.error
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            req = Request(
                f"{scheme}://{ip}:{port}/",
                headers={"User-Agent": "eagleEyes/5.0"},
            )
            with urlopen(req, timeout=timeout, context=ctx) as resp:
                headers = dict(resp.headers)
                body = resp.read(16384).decode(errors="ignore")
                final_url = resp.geturl()
                return headers, body, final_url
        except Exception as e:
            if hasattr(e, "headers") and e.headers:
                return dict(e.headers), "", getattr(e, "url", "") or ""
            return {}, "", ""

    try:
        headers, body, final_url = await asyncio.wait_for(
            loop.run_in_executor(None, fetch), timeout=timeout + 2
        )
    except asyncio.TimeoutError:
        return []

    for url in [headers.get("Location", ""), headers.get("location", ""), final_url]:
        domain = _extract_domain_from_url(url)
        if domain:
            found.append(domain)

    for pattern in [
        r'<meta[^>]+content=["\'][^"\']*(?:url=)?https?://([a-zA-Z0-9._-]+)',
        r'<link[^>]+rel=["\']canonical["\'][^>]+href=["\']https?://([a-zA-Z0-9._-]+)',
        r'href=["\']https?://([a-zA-Z0-9._-]+)',
    ]:
        for m in re.finditer(pattern, body, re.IGNORECASE):
            domain = m.group(1).lower().rstrip(".")
            if _is_valid_domain(domain):
                found.append(domain)

    server_hdr = headers.get("Server", headers.get("server", ""))
    if "." in server_hdr:
        maybe_domain = re.search(r"([a-zA-Z0-9._-]+\.[a-zA-Z]{2,})", server_hdr)
        if maybe_domain:
            found.append(maybe_domain.group(1).lower())

    return list(set(d for d in found if _is_valid_domain(d)))

def _extract_domain_from_url(url: str) -> str:
    if not url:
        return ""
    m = re.match(r"https?://([a-zA-Z0-9._-]+)", url)
    if m:
        host = m.group(1).lower()
        if _is_valid_domain(host):
            return host
    return ""

def _is_valid_domain(s: str) -> bool:
    if not s or len(s) > 253:
        return False
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", s):
        return False
    return bool(re.match(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$", s))

async def crt_sh_fanout(domains: list[str], config: dict) -> dict[str, list[str]]:
    results = {}
    concurrency = 5
    sem = asyncio.Semaphore(concurrency)

    async def query_one(domain: str) -> None:
        async with sem:
            subs = await query_crt_sh(domain, config)
            if subs:
                results[domain] = subs

    apex_domains = set()
    for d in domains:
        parts = d.split(".")
        if len(parts) >= 2:
            apex = ".".join(parts[-2:])
            apex_domains.add(apex)

    await asyncio.gather(*[query_one(d) for d in apex_domains])
    return results

def merge_domains(host: dict) -> None:
    all_domains = set()
    dom = host.get("domains", {})
    for key in ("ptr", "ssl_cn", "ssl_sans", "http_headers", "crt_sh", "passive_api"):
        for d in dom.get(key, []):
            d = d.lower().strip().lstrip("*.")
            if d and _is_valid_domain(d):
                all_domains.add(d)
    host["domains"]["all"] = sorted(all_domains)

async def run_domain_extractor(state: dict, config: dict) -> None:
    alive_hosts = {ip: h for ip, h in state["hosts"].items() if h.get("status") == "alive"}
    if not alive_hosts:
        print("  [Phase 5] No alive hosts for domain extraction.")
        return

    print(f"\n  [Phase 5] Domain Extraction — {len(alive_hosts)} hosts")

    print("    PTR lookups...")
    ptr_results = await reverse_dns_bulk(list(alive_hosts.keys()), config)
    for ip, hostnames in ptr_results.items():
        if ip in state["hosts"] and hostnames:
            state["hosts"][ip]["domains"]["ptr"] = hostnames

    ssl_sem = asyncio.Semaphore(config.get("rate_limits", {}).get("ssl_concurrent", 50))
    http_sem = asyncio.Semaphore(config.get("rate_limits", {}).get("http_concurrent", 50))

    async def extract_host(ip: str, host: dict) -> None:
        tcp_ports = set(host["ports"]["tcp"].keys())

        async with ssl_sem:
            ssl_results = await extract_ssl_all_ports(ip, tcp_ports, config)
        for port, ssl_data in ssl_results.items():
            cn = ssl_data.get("cn", "")
            sans = ssl_data.get("sans", [])
            if cn and _is_valid_domain(cn):
                host["domains"]["ssl_cn"].append(cn)
                host["services"].setdefault(port, {})
                host["services"][port]["ssl"] = ssl_data
            host["domains"]["ssl_sans"].extend(s for s in sans if _is_valid_domain(s))

        http_ports = tcp_ports & (HTTP_PORTS | TLS_PORTS)
        async with http_sem:
            http_tasks = [extract_http_domains(ip, p, config) for p in http_ports]
            http_results = await asyncio.gather(*http_tasks, return_exceptions=True)
        for result in http_results:
            if isinstance(result, list):
                host["domains"]["http_headers"].extend(result)

        for key in ("ssl_cn", "ssl_sans", "http_headers"):
            host["domains"][key] = list(set(host["domains"][key]))

    await asyncio.gather(*[extract_host(ip, host) for ip, host in alive_hosts.items()])

    all_discovered = set()
    for host in alive_hosts.values():
        for key in ("ptr", "ssl_cn", "ssl_sans", "http_headers", "passive_api"):
            all_discovered.update(host["domains"].get(key, []))

    if all_discovered:
        print(f"    crt.sh lookup on {len(all_discovered)} domains...")
        crt_results = await crt_sh_fanout(list(all_discovered), config)

        for ip, host in alive_hosts.items():
            host_domains = set()
            for key in ("ptr", "ssl_cn", "ssl_sans", "http_headers", "passive_api"):
                host_domains.update(host["domains"].get(key, []))
            for domain in host_domains:
                parts = domain.split(".")
                apex = ".".join(parts[-2:]) if len(parts) >= 2 else domain
                if apex in crt_results:
                    host["domains"]["crt_sh"].extend(crt_results[apex])
            host["domains"]["crt_sh"] = list(set(host["domains"]["crt_sh"]))

    for host in alive_hosts.values():
        merge_domains(host)
        host["scan_timestamps"]["domain_extraction"] = _now()

    total_domains = sum(len(h["domains"]["all"]) for h in alive_hosts.values())
    state["stats"]["domains_extracted"] = total_domains
    state["stats"]["phases_completed"].append("domain_extraction")
    print(f"  [Phase 5] Complete — {total_domains} domains extracted")

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
