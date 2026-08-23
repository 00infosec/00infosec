from __future__ import annotations

import asyncio
import hashlib
import re
from urllib.parse import urljoin

from .base import Module

JS_URL_RE = re.compile(r"['\"`]([^'\"`\s<>]+\.js(?:\?[^'\"`\s]*)?)['\"`]")
SOURCE_MAP_RE = re.compile(r"//[@#]\s*sourceMappingURL\s*=\s*(.+)$")

SECRET_PATTERNS = [
    ("aws_access_key", r"AKIA[0-9A-Z]{16}", "high"),
    ("aws_secret", r"(?i)aws_secret[_a-z]*\s*[:=]\s*['\"]([0-9a-zA-Z/+]{40})['\"]", "high"),
    ("gcp_api_key", r"AIza[0-9A-Za-z\-_]{35}", "high"),
    ("gcp_service_account", r"\"type\"\s*:\s*\"service_account\"", "critical"),
    ("azure_storage", r"AccountKey=([0-9a-zA-Z+/=]{88})", "high"),
    ("github_pat", r"ghp_[0-9a-zA-Z]{36}", "critical"),
    ("gitlab_pat", r"glpat-[0-9a-zA-Z\-_]{20}", "high"),
    ("slack_token", r"xox[abprs]-[0-9a-zA-Z\-]{10,}", "high"),
    ("stripe_secret", r"sk_live_[0-9a-zA-Z]{24,}", "critical"),
    ("paypal_braintree", r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}", "critical"),
    ("sendgrid_key", r"SG\.[0-9a-zA-Z\-_]{22}\.[0-9a-zA-Z\-_]{43}", "high"),
    ("jwt_token", r"eyJ[A-Za-z0-9_/+\-=]{20,}\.eyJ[A-Za-z0-9_/+\-=]{20,}\.[A-Za-z0-9_/+\-=]+", "medium"),
    ("private_key_rsa", r"-----BEGIN RSA PRIVATE KEY-----", "critical"),
    ("private_key_pem", r"-----BEGIN PRIVATE KEY-----", "critical"),
    ("private_key_ssh", r"-----BEGIN OPENSSH PRIVATE KEY-----", "critical"),
    ("password_assign", r"(?i)(?:password|passwd|pwd|secret|api[_-]?key|token)\s*[:=]\s*['\"]([^'\"]{8,80})['\"]", "medium"),
    ("openai_key", r"sk-(?:proj-)?[A-Za-z0-9]{20,}", "medium"),
    ("anthropic_key", r"sk-ant-[a-zA-Z0-9\-_]{90,}", "high"),
    ("hardcoded_jdbc", r"jdbc:[a-z]+://[^\s'\";]+", "medium"),
]

ENDPOINT_PATTERNS = [
    re.compile(p) for p in (
        r"['\"`](/api/v?\d?/[a-zA-Z0-9_\-/.{}:]+)['\"`]",
        r"['\"`](/v\d/[a-zA-Z0-9_\-/.{}:]+)['\"`]",
        r"['\"`](/admin/[a-zA-Z0-9_\-/.{}:]+)['\"`]",
        r"['\"`](/internal/[a-zA-Z0-9_\-/.{}:]+)['\"`]",
        r"['\"`](/graphql/?[a-zA-Z0-9_\-/.{}:]*)['\"`]",
        r"['\"`](/auth/[a-zA-Z0-9_\-/.{}:]+)['\"`]",
        r"['\"`](https?://[a-zA-Z0-9\-.]+/(?:api|admin|internal|v\d)/[^'\"`\s]+)['\"`]",
    )
]

SENSITIVE_PATHS = [
    ("/.git/HEAD", "git_head", "critical", r"ref:\s*refs/"),
    ("/.git/config", "git_config", "critical", r"\[(?:core|remote|branch)"),
    ("/.env", "dotenv", "critical", r"[A-Z_]+="),
    ("/.env.production", "dotenv_prod", "critical", r"[A-Z_]+="),
    ("/.env.backup", "dotenv_backup", "critical", r"[A-Z_]+="),
    ("/web.config", "web_config", "high", r"<configuration"),
    ("/appsettings.json", "dotnet_config", "high", r"ConnectionStrings|AppSettings"),
    ("/config/database.yml", "rails_db", "critical", r"(?:adapter|database|password):"),
    ("/phpinfo.php", "phpinfo", "high", r"phpinfo\(\)|PHP Version"),
    ("/actuator/env", "spring_env", "critical", r"propertySources|activeProfiles"),
    ("/actuator/health", "spring_health", "medium", r"status"),
    ("/swagger.json", "swagger_json", "medium", r"swagger|openapi"),
    ("/openapi.json", "openapi_json", "medium", r"openapi"),
    ("/api-docs", "api_docs", "medium", r"swagger|openapi|info"),
    ("/graphql", "graphql_intro", "medium", r"__schema|introspection"),
    ("/backup.sql", "backup_sql", "critical", r"INSERT INTO|CREATE TABLE|DROP TABLE"),
    ("/dump.sql", "dump_sql", "critical", r"INSERT INTO|CREATE TABLE|DROP TABLE"),
    ("/credentials.json", "gcp_creds", "critical", r"type.*service_account"),
]


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    from collections import Counter
    n = len(s)
    return -sum((c / n) * __import__("math").log2(c / n)
                for c in Counter(s).values())


STRONG_SECRET_TYPES = {
    "aws_access_key", "aws_secret", "gcp_api_key", "gcp_service_account",
    "azure_storage", "github_pat", "gitlab_pat", "slack_token",
    "stripe_secret", "paypal_braintree", "sendgrid_key", "private_key_rsa",
    "private_key_pem", "private_key_ssh",
}


class JsLeakModule(Module):
    name = "jsleak"
    description = "JS bundle analysis: secrets, endpoints, source maps, exposures"
    provides = ("secrets", "endpoints")
    requires = ("subdomains", "hosts_alive")

    async def run(self):
        urls: set = set()
        for u in self.ctx.data.get("urls") or ():
            if u.lower().startswith(("http://", "https://")) and ".js" in u.lower():
                urls.add(u)
        js_urls, endpoints, secrets, maps, high_entropy = set(urls), {}, [], [], []
        errors: dict[str, list] = {}

        alive = sorted(self.ctx.data.get("hosts_alive") or [])[:200]
        pages = [f"https://{h}/" for h in alive]
        sem = asyncio.Semaphore(12)

        async def probe_page(u):
            async with sem:
                try:
                    r = await self.http.get(u, timeout=20, max_body=300_000,
                                            scoped=True)
                    if r.ok:
                        for m in JS_URL_RE.finditer(r.body):
                            ju = urljoin(u, m.group(1))
                            if ju.startswith(("http://", "https://")):
                                js_urls.add(ju)
                except Exception as e:
                    errors.setdefault("discover", []).append(f"{u}: {str(e)[:80]}")

        await asyncio.gather(*(probe_page(u) for u in pages[:50]))

        async def analyze(ju):
            async with sem:
                try:
                    r = await self.http.get(ju, timeout=60, max_body=1_500_000,
                                            scoped=True)
                    if not r.ok:
                        return
                    body = r.body
                    for name, pat, sev in SECRET_PATTERNS:
                        for m in re.finditer(pat, body):
                            val = m.group(1) if m.groups() and m.group(1) else m.group(0)
                            if str(val).lower() in ("undefined", "null", "true",
                                                    "false", "example", "password"):
                                continue
                            ctx_txt = body[max(0, m.start() - 40):m.end() + 40]
                            strong = name in STRONG_SECRET_TYPES
                            secrets.append({"type": name, "value": str(val)[:200],
                                            "severity": sev, "source_url": ju,
                                            "context": ctx_txt.replace("\n", " ")[:200]})
                            self.add("js_secret", sev, ju,
                                     evidence={"type": name, "value": str(val)[:200]},
                                     status="finding" if strong else "candidate",
                                     confidence="high" if strong else "medium")
                    for rx in ENDPOINT_PATTERNS:
                        for m in rx.finditer(body):
                            ep = m.group(1).strip()
                            if 1 < len(ep) < 200 and (ju, ep) not in endpoints:
                                endpoints[(ju, ep)] = True
                    sm = SOURCE_MAP_RE.search(body)
                    if sm:
                        map_url = urljoin(ju, sm.group(1).strip())
                        try:
                            mr = await self.http.get(map_url, timeout=30,
                                                     max_body=500_000)
                            accessible = mr.status == 200
                            sources_count = 0
                            if accessible:
                                try:
                                    j = __import__("json").loads(mr.body)
                                    sources_count = len(j.get("sources") or [])
                                except Exception:
                                    pass
                            maps.append({"js_url": ju, "map_url": map_url,
                                         "accessible": accessible,
                                         "sources": sources_count})
                            if sources_count:
                                self.add("source_map_exposed", "low", ju,
                                         evidence={"map_url": map_url,
                                                   "sources": sources_count},
                                         status="observation",
                                         confidence="high")
                        except Exception:
                            pass
                    for m in re.finditer(r"['\"`]([A-Za-z0-9+/_\-=]{32,})['\"`]", body):
                        v = m.group(1)
                        ent = shannon_entropy(v)
                        if ent >= 4.5 and len(v) <= 200:
                            high_entropy.append({"value": v[:120],
                                                 "entropy": round(ent, 2),
                                                 "source_url": ju})
                except Exception as e:
                    errors.setdefault(ju, []).append(str(e)[:100])

        await asyncio.gather(*(analyze(j) for j in list(js_urls)[:400]))

        exposed = await self.exposure_scan(alive)
        self.ctx.data["secrets"] = secrets
        self.ctx.data["endpoints"] = [{"endpoint": ep, "found_in": ju}
                                      for (ju, ep) in endpoints]
        self.ctx.data["source_maps"] = maps
        self.result.stats.update({
            "js_files": len(js_urls), "js_from_recon_urls": len(urls),
            "secrets": len(secrets),
            "endpoints": len(endpoints), "source_maps": sum(1 for x in maps
                                                            if x["accessible"]),
            "exposed_files": len(exposed), "high_entropy": len(high_entropy),
        })
        self.ctx.data["js_exposed"] = exposed

    async def exposure_scan(self, hosts):
        found = []
        sem = asyncio.Semaphore(15)

        async def one(host):
            async with sem:
                fp = await self.fingerprint_404(host)
                for path, name, sev, validator in SENSITIVE_PATHS:
                    for scheme in ("https", "http"):
                        url = f"{scheme}://{host}{path}"
                        try:
                            r = await self.http.request(
                                "GET", url, timeout=12, allow_redirects=False,
                                max_body=20_000, scoped=True)
                        except Exception:
                            continue
                        if r.status != 200 or not r.body:
                            continue
                        body = r.body
                        if fp and abs(len(body) - fp[0]) < 50 and \
                                hashlib.md5(body[:512].encode(errors="ignore")).hexdigest() == fp[1]:
                            break
                        if validator and not re.search(validator, body[:4096], re.I):
                            break
                        found.append({"url": url, "path": path, "name": name,
                                      "severity": sev, "host": host})
                        self.add("exposed_file", sev, host,
                                 evidence={"path": path,
                                           "validator": validator[:40] if validator else "",
                                           "anti_soft404": bool(fp)},
                                 status="finding", confidence="high")
                        break
        await asyncio.gather(*(one(h) for h in hosts[:150]))
        return found

    async def fingerprint_404(self, host):
        try:
            r = await self.http.get(
                f"https://{host}/{__import__('os').urandom(8).hex()}-nx.html",
                timeout=10, max_body=10_000)
            if r.status == 200:
                h = hashlib.md5(r.body[:512].encode(errors="ignore")).hexdigest()
                return (len(r.body), h)
        except Exception:
            pass
        return None
