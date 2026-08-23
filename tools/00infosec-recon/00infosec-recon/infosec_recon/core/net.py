from __future__ import annotations

import re

COMPOUND_SUFFIXES = {
    "com.br", "net.br", "org.br", "gov.br", "edu.br", "mil.br", "art.br",
    "b.br", "eco.br", "emp.br", "ind.br", "inf.br", "jus.br", "leg.br",
    "mp.br", "tur.br", "tv.br", "blog.br", "app.br", "dev.br", "srv.br",
    "far.br", "imb.br", "rec.br", "psi.br", "adv.br", "eng.br", "esp.br",
    "agr.br", "am.br", "fm.br", "g12.br", "vet.br", "etc.br",
    "co.uk", "org.uk", "gov.uk", "ac.uk", "me.uk",
    "com.au", "net.au", "org.au", "gov.au", "edu.au",
    "co.jp", "co.nz", "co.za", "co.in", "co.kr",
    "com.mx", "com.ar", "com.co", "com.tr", "com.cn", "com.tw", "com.hk",
    "com.sg", "com.my", "com.ph", "com.pt", "com.es",
}

HOST_RE = re.compile(r"^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", re.I)


def split_registrable(domain: str) -> tuple[str, str]:
    d = (domain or "").strip().strip(".").lower()
    d = d.split("/")[0].split(":")[0]
    parts = [p for p in d.split(".") if p]
    if len(parts) < 2:
        return (parts[0] if parts else d), ""
    if ".".join(parts[-2:]) in COMPOUND_SUFFIXES and len(parts) >= 3:
        return parts[-3], ".".join(parts[-2:])
    return parts[-2], parts[-1]


def registrable_core(domain: str) -> str:
    return split_registrable(domain)[0]


def sanitize_slug(name: str) -> str:
    slug = re.sub(r"[^a-z0-9._-]+", "_", (name or "").lower())[:60]
    return slug or "target"


def normalize_host(raw: str, base_domain: str) -> str | None:
    h = (raw or "").strip().lower().strip(".")
    h = re.sub(r"^\*\.", "", h)
    if "://" in h:
        try:
            from urllib.parse import urlparse
            h = urlparse(h).hostname or ""
        except Exception:
            return None
    h = h.strip(".")
    if not h or not HOST_RE.match(h):
        return None
    if h == base_domain or h.endswith("." + base_domain):
        return h
    return None


def extract_hosts_from_text(text: str, base_domain: str) -> set[str]:
    esc = re.escape(base_domain)
    rx = re.compile(rf"([a-z0-9](?:[a-z0-9\-_.]{{0,253}}[a-z0-9])?\.{esc})", re.I)
    out = set()
    for m in rx.finditer(text or ""):
        h = normalize_host(m.group(1), base_domain)
        if h:
            out.add(h)
    return out
