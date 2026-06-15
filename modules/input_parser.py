
import asyncio
import ipaddress
import re
from pathlib import Path
from typing import Generator

def is_cidr(s: str) -> bool:
    return "/" in s and not s.startswith("http")

def is_ip_range(s: str) -> bool:
    return bool(re.match(r"^[\d.]+-[\d.]+$", s.strip()))

def is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s.strip())
        return True
    except ValueError:
        return False

def is_domain(s: str) -> bool:
    s = s.strip()
    return bool(re.match(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$", s))

def is_rfc1918(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False

def classify_network(targets: list[str]) -> str:
    for ip in targets[:10]:
        if not is_rfc1918(ip):
            return "public"
    return "local"

def expand_cidr(cidr: str) -> Generator[str, None, None]:
    net = ipaddress.ip_network(cidr, strict=False)
    for ip in net.hosts():
        yield str(ip)

def expand_range(range_str: str) -> Generator[str, None, None]:
    m = re.match(r"^([\d.]+)-([\d.]+)$", range_str.strip())
    if not m:
        return
    try:
        start = int(ipaddress.ip_address(m.group(1)))
        end = int(ipaddress.ip_address(m.group(2)))
        for i in range(start, end + 1):
            yield str(ipaddress.ip_address(i))
    except ValueError:
        return

async def resolve_domain(domain: str) -> list[str]:
    try:
        loop = asyncio.get_event_loop()
        results = await loop.run_in_executor(
            None, lambda: asyncio.run(_resolve(domain))
        )
        return results
    except Exception:
        return []

async def _resolve(domain: str) -> list[str]:
    loop = asyncio.get_event_loop()
    try:
        info = await loop.getaddrinfo(domain, None)
        return list({r[4][0] for r in info})
    except Exception:
        return []

def _parse_token(token: str) -> tuple[str, any]:
    token = token.strip()
    if not token or token.startswith("#"):
        return "skip", None
    if token.startswith("@"):
        return "file", token[1:]
    if is_cidr(token):
        return "cidr", token
    if is_ip_range(token):
        return "range", token
    if is_ip(token):
        return "ip", token
    if is_domain(token):
        return "domain", token
    return "unknown", token

def _read_file_targets(filepath: str) -> list[str]:
    path = Path(filepath)
    if not path.exists():
        raise FileNotFoundError(f"Target file not found: {filepath}")
    tokens = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            tokens.append(line)
    return tokens

class TargetSet:
    def __init__(self):
        self._cidrs: list[str] = []
        self._single_ips: list[str] = []
        self._domains: list[str] = []
        self._resolved: dict[str, list[str]] = {}
        self._estimated_count: int = 0
        self.network_type: str = "public"

    def add_cidr(self, cidr: str) -> None:
        self._cidrs.append(cidr)
        net = ipaddress.ip_network(cidr, strict=False)
        self._estimated_count += net.num_addresses - 2 or 1

    def add_ip(self, ip: str) -> None:
        self._single_ips.append(ip)
        self._estimated_count += 1

    def add_domain(self, domain: str) -> None:
        self._domains.append(domain)

    def set_resolved(self, domain: str, ips: list[str]) -> None:
        self._resolved[domain] = ips
        self._single_ips.extend(ips)
        self._estimated_count += len(ips)

    @property
    def estimated_count(self) -> int:
        return self._estimated_count

    @property
    def unresolved_domains(self) -> list[str]:
        return [d for d in self._domains if d not in self._resolved]

    @property
    def cidrs(self) -> list[str]:
        return list(self._cidrs)

    def ip_generator(self) -> Generator[str, None, None]:
        for ip in self._single_ips:
            yield ip
        for cidr in self._cidrs:
            yield from expand_cidr(cidr)

    def ip_list(self) -> list[str]:
        return list(self.ip_generator())

    def is_large(self) -> bool:
        return self._estimated_count > 65536

    def summary(self) -> str:
        parts = []
        if self._cidrs:
            parts.append(f"{len(self._cidrs)} CIDR(s)")
        if self._single_ips:
            parts.append(f"{len(self._single_ips)} IP(s)")
        if self._domains:
            parts.append(f"{len(self._domains)} domain(s)")
        return ", ".join(parts) or "empty"

async def parse_targets(raw_inputs: list[str]) -> TargetSet:
    target_set = TargetSet()
    tokens = []

    for raw in raw_inputs:
        kind, value = _parse_token(raw)
        if kind == "file":
            try:
                tokens.extend(_read_file_targets(value))
            except FileNotFoundError as e:
                print(f"[!] {e}")
        elif kind != "skip":
            tokens.append(raw)

    for token in tokens:
        kind, value = _parse_token(token)
        if kind == "cidr":
            target_set.add_cidr(value)
        elif kind == "range":
            for ip in expand_range(value):
                target_set.add_ip(ip)
        elif kind == "ip":
            target_set.add_ip(value)
        elif kind == "domain":
            target_set.add_domain(value)
        elif kind == "unknown":
            print(f"[!] Unrecognised target format, skipping: {token!r}")

    if target_set.unresolved_domains:
        tasks = [_resolve(d) for d in target_set.unresolved_domains]
        results = await asyncio.gather(*tasks)
        for domain, ips in zip(target_set.unresolved_domains, results):
            if ips:
                target_set.set_resolved(domain, ips)
            else:
                print(f"[!] Could not resolve domain: {domain}")

    sample = target_set._single_ips[:20]
    if not sample and target_set._cidrs:
        first = next(expand_cidr(target_set._cidrs[0]), None)
        if first:
            sample = [first]
    target_set.network_type = classify_network(sample)

    return target_set
