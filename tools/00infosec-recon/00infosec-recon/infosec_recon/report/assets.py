from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse


def build_asset_inventory(ctx) -> list[dict]:
    """Correlate the collected module data into deterministic asset records."""
    data = ctx.data
    assets: dict[str, dict] = {}

    def kind_for(value: str) -> str:
        try:
            ipaddress.ip_address(value)
            return "ip"
        except ValueError:
            pass
        if "@" in value and "." in value:
            return "identity"
        if value == ctx.domain:
            return "domain"
        if value.endswith("." + ctx.domain):
            return "subdomain"
        return "external"

    def ensure(value: str, kind: str | None = None) -> dict:
        value = str(value or "").strip().lower().strip(".")
        if value.startswith(("http://", "https://")):
            value = (urlparse(value).hostname or value).lower()
        if not value:
            value = ctx.domain
        rec = assets.setdefault(value, {
            "asset": value, "kind": kind or kind_for(value),
            "ips": set(), "cnames": set(), "hosts": set(), "ports": set(),
            "urls": {}, "technologies": {}, "cves": set(),
            "endpoints": set(), "findings": [], "cloud": [],
        })
        if kind and rec["kind"] == "external":
            rec["kind"] = kind
        return rec

    ensure(ctx.domain, "domain")
    alive = set(data.get("hosts_alive") or ())
    for host in set(data.get("subdomains") or ()) | alive:
        rec = ensure(host)
        if host in alive:
            rec["alive"] = True

    for dns in data.get("dns_records") or []:
        host = dns.get("host")
        if not host:
            continue
        rec = ensure(host)
        rec["alive"] = bool(dns.get("alive"))
        for ip in (dns.get("A") or []) + (dns.get("AAAA") or []):
            rec["ips"].add(ip)
            ensure(ip, "ip")["hosts"].add(host)
        rec["cnames"].update(dns.get("CNAME") or [])
        for cname in dns.get("CNAME") or []:
            ensure(cname)["hosts"].add(host)

    for url in data.get("urls") or []:
        host = urlparse(url).hostname
        if host:
            ensure(host)["urls"].setdefault(url, {"url": url})

    for http in data.get("http_records") or []:
        host = http.get("host") or urlparse(http.get("url", "")).hostname
        if not host:
            continue
        rec = ensure(host)
        url = http.get("url")
        if url:
            rec["urls"][url] = {
                k: http.get(k) for k in ("url", "status", "title", "server")
                if http.get(k) not in (None, "")
            }

    for host, techs in (data.get("stack") or {}).items():
        rec = ensure(host)
        for name, info in techs.items():
            info = info if isinstance(info, dict) else {}
            rec["technologies"][name] = {
                k: info.get(k) for k in ("version", "category") if info.get(k)
            }

    for ip, info in (data.get("internetdb") or {}).items():
        rec = ensure(ip, "ip")
        rec["ports"].update(int(p) for p in info.get("ports", []) if str(p).isdigit())

    for cve in data.get("cves") or []:
        for host in cve.get("matched_hosts") or []:
            if cve.get("id"):
                ensure(host)["cves"].add(cve["id"])

    for endpoint in data.get("endpoints") or []:
        host = urlparse(endpoint.get("found_in", "")).hostname
        if host and endpoint.get("endpoint"):
            ensure(host)["endpoints"].add(endpoint["endpoint"])

    root = ensure(ctx.domain, "domain")
    for bucket in data.get("buckets") or []:
        if bucket.get("open"):
            root["cloud"].append({k: bucket.get(k) for k in
                                  ("provider", "name", "url", "attributed")})

    for typo in data.get("typosquats") or []:
        domain = typo.get("domain")
        if domain:
            rec = ensure(domain, "external_domain")
            rec["risk_score"] = typo.get("score", 0)

    for finding in ctx.findings:
        targets = finding.evidence.get("hosts") or [finding.asset]
        for target in targets:
            rec = ensure(target)
            if finding.type == "open_port":
                port = finding.evidence.get("port")
                if port is None:
                    match = re.search(r"\bport\s+(\d+)",
                                      str(finding.evidence.get("summary", "")), re.I)
                    port = int(match.group(1)) if match else None
                if port is not None and str(port).isdigit():
                    rec["ports"].add(int(port))
            if finding.type in ("vulnerable_cve", "internetdb_cve"):
                cve = finding.evidence.get("cve") or \
                    finding.evidence.get("summary")
                if cve and str(cve).upper().startswith("CVE-"):
                    rec["cves"].add(str(cve).upper())
            rec["findings"].append({
                "module": finding.module, "type": finding.type,
                "status": finding.status, "severity": finding.severity,
                "confidence": finding.confidence,
                "evidence": finding.evidence,
            })

    out = []
    for rec in assets.values():
        normalized = {"asset": rec["asset"], "kind": rec["kind"]}
        if rec.get("alive"):
            normalized["alive"] = True
        for key in ("ips", "cnames", "hosts", "ports", "cves", "endpoints"):
            if rec[key]:
                normalized[key] = sorted(rec[key])
        if rec["urls"]:
            normalized["urls"] = [rec["urls"][u] for u in sorted(rec["urls"])]
        if rec["technologies"]:
            normalized["technologies"] = {
                name: rec["technologies"][name] for name in sorted(rec["technologies"])
            }
        if rec["findings"]:
            normalized["findings"] = sorted(
                rec["findings"], key=lambda f: (f["type"], f["module"]))
        if rec["cloud"]:
            normalized["cloud"] = sorted(rec["cloud"], key=lambda b: (
                str(b.get("provider")), str(b.get("name"))))
        if "risk_score" in rec:
            normalized["risk_score"] = rec["risk_score"]
        out.append(normalized)
    return sorted(out, key=lambda r: (r["kind"], r["asset"]))
