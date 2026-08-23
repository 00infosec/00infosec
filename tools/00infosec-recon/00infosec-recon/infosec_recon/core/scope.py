from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from urllib.parse import urlparse

from .net import HOST_RE


class ScopeBlocked(ConnectionError):
    def __init__(self, url: str, reason: str):
        self.url = url
        self.reason = reason
        super().__init__(f"bloqueado pelo escopo ({reason}): {url}")


PRIVATE_NETS = [
    ipaddress.ip_network(n)
    for n in (
        "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
        "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.168.0.0/16",
        "198.18.0.0/15", "224.0.0.0/3", "::1/128", "fc00::/7", "fe80::/10",
        "ff00::/8",
    )
]


def _ip_risk(ip: str) -> list[str]:
    reasons = []
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return ["ip_invalido"]
    if a.is_loopback:
        reasons.append("loopback")
    if a.is_link_local:
        reasons.append("link_local")
    if a.is_reserved or a.is_multicast or a.is_unspecified:
        reasons.append("reservado")
    if any(a in net for net in PRIVATE_NETS):
        reasons.append("privado")
    return reasons


@dataclass
class Scope:
    domain: str
    include_subdomains: bool = True
    allow_private_ips: bool = False
    excluded_hosts: set = field(default_factory=set)
    blocked: list = field(default_factory=list)

    def host_in_scope(self, host: str) -> bool:
        h = (host or "").lower().strip(".")
        if not h:
            return False
        if h in self.excluded_hosts:
            return False
        return h == self.domain or (
            self.include_subdomains and h.endswith("." + self.domain))

    def check_host(self, host: str) -> tuple[bool, str]:
        h = (host or "").lower().strip(".")
        if not h or len(h) > 253 or not HOST_RE.match(h):
            return False, "hostname_invalido"
        if not self.host_in_scope(h):
            return False, "fora_do_escopo"
        return True, ""

    def ip_allowed(self, ip: str) -> tuple[bool, str]:
        risks = _ip_risk(ip)
        if not risks:
            return True, ""
        if self.allow_private_ips and set(risks) <= {"privado"}:
            return True, ""
        return False, "+".join(risks)

    def url_allowed(self, url: str) -> tuple[bool, str]:
        try:
            p = urlparse(url)
        except Exception:
            return False, "url_invalida"
        if p.scheme not in ("http", "https"):
            return False, f"esquema_{p.scheme or 'vazio'}"
        host = p.hostname
        if not host:
            return False, "sem_host"
        try:
            ipaddress.ip_address(host)
        except ValueError:
            return self.check_host(host)
        ok, why = self.ip_allowed(host)
        return (True, "") if ok else (False, why)

    def note_blocked(self, url: str, reason: str):
        if len(self.blocked) < 500:
            self.blocked.append({"url": url[:300], "reason": reason})

    def guard_url(self, url: str) -> None:
        ok, why = self.url_allowed(url)
        if not ok:
            self.note_blocked(url, why)
            raise ScopeBlocked(url, why)


def validate_domain(domain: str) -> str:
    d = (domain or "").strip().lower()
    d = d.removeprefix("https://").removeprefix("http://").strip("/")
    d = d.split("/")[0].split(":")[0]
    if not d or len(d) > 253 or not HOST_RE.match(d):
        raise ValueError(f"domínio inválido: {domain!r}")
    return d


def build_scope(domain: str, args) -> Scope:
    return Scope(
        domain=domain,
        include_subdomains=True,
        allow_private_ips=bool(getattr(args, "allow_private", False)),
        excluded_hosts={h.lower() for h in
                        (getattr(args, "exclude_host", "") or "").split(",") if h},
    )
