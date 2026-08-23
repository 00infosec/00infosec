from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from urllib.parse import quote

from ..core.net import split_registrable
from .base import Module

try:
    import dns.asyncresolver
    HAS_DNS = True
except ImportError:
    HAS_DNS = False

HOMO_SUBS = {
    "o": ["0"], "0": ["o"], "l": ["1", "i"], "i": ["1", "l"],
    "e": ["3"], "3": ["e"], "a": ["@"], "s": ["5"], "5": ["s"],
    "g": ["q", "9"], "b": ["6", "8"], "z": ["2"], "n": ["m"], "u": ["v"],
    "v": ["u"], "c": ["k"], "k": ["c"],
}
ALT_TLDS = ["com", "net", "org", "info", "biz", "co", "io", "app", "cloud",
            "online", "site", "xyz", "top", "shop", "tech", "br", "com.br"]
PHISH_WORDS = ["login", "secure", "auth", "account", "verify", "support",
               "banking", "online", "portal", "app"]


def generate_typosquats(domain: str, max_per_method: int = 40) -> set:
    base, tld = split_registrable(domain)
    variants: set = set()
    for i, ch in enumerate(base):
        for sub in HOMO_SUBS.get(ch, []):
            v = base[:i] + sub + base[i + 1:]
            if len(v) >= 3:
                variants.add(f"{v}.{tld}")
    for i in range(1, len(base)):
        for ins in "abcdefghijklmnopqrstuvwxyz0123456789-":
            v = base[:i] + ins + base[i:]
            if len(v) <= 30:
                variants.add(f"{v}.{tld}")
    for i in range(len(base)):
        v = base[:i] + base[i + 1:]
        if len(v) >= 3:
            variants.add(f"{v}.{tld}")
    for i in range(len(base) - 1):
        v = base[:i] + base[i + 1] + base[i] + base[i + 2:]
        variants.add(f"{v}.{tld}")
    for t in ALT_TLDS:
        if t != tld and len(base) <= 25:
            variants.add(f"{base}.{t}")
    for w in PHISH_WORDS:
        variants.add(f"{w}-{base}.{tld}")
        variants.add(f"{base}-{w}.{tld}")
    variants.discard(domain.lower())
    return variants


class PhishLabModule(Module):
    name = "phishlab"
    description = "typosquatting infra: DNS sweep + CT logs + urlscan"
    provides = ("typosquats",)
    requires = ()

    async def run(self):
        d = self.ctx.domain
        max_cand = getattr(self.ctx.args, "max_candidates", 400)
        candidates = sorted(generate_typosquats(d))[:max_cand]
        self.result.stats["candidates"] = len(candidates)

        live_dns = []
        if HAS_DNS:
            resolver = dns.asyncresolver.Resolver()
            resolver.nameservers = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
            resolver.timeout = 3
            resolver.lifetime = 5
            sem = asyncio.Semaphore(30)

            async def check(dom):
                async with sem:
                    ips, mx = [], []
                    try:
                        a = await resolver.resolve(dom, "A")
                        ips = [r.to_text() for r in a]
                    except Exception:
                        pass
                    try:
                        mxans = await resolver.resolve(dom, "MX")
                        mx = [r.exchange.to_text().strip(".") for r in mxans]
                    except Exception:
                        pass
                    if ips or mx:
                        live_dns.append({"domain": dom, "ips": ips[:4], "mx": mx[:3]})
                    else:
                        pass

            await asyncio.gather(*(check(c) for c in candidates))
        else:
            self.result.stats["dns"] = "skipped (no dnspython)"

        ct_recent = await self.src_ct_recent(d)
        urlscan_hits = await self.src_urlscan(d)

        scored = {}
        for rec in live_dns:
            s = scored.setdefault(rec["domain"], {"domain": rec["domain"],
                                                  "ips": rec["ips"], "mx": rec["mx"]})
            s["in_dns"] = True
            s.setdefault("score", 0)
            s["score"] += 30
            if rec["mx"]:
                s["score"] += 20
        for e in ct_recent:
            dom = e.get("domain")
            if not dom:
                continue
            s = scored.setdefault(dom, {"domain": dom})
            s["in_ct"] = True
            s["ct_issued"] = e.get("issued")
            s.setdefault("score", 0)
            s["score"] += 25
        for u in urlscan_hits:
            dom = u.get("domain")
            if not dom:
                continue
            s = scored.setdefault(dom, {"domain": dom})
            s["in_urlscan"] = True
            s["urlscan_url"] = u.get("url")
            s.setdefault("score", 0)
            s["score"] += 15
        for s in scored.values():
            if any(w in s["domain"] for w in PHISH_WORDS):
                s["score"] = s.get("score", 0) + 10
                s["phish_word"] = True

        suspicious = sorted(scored.values(),
                            key=lambda x: -x.get("score", 0))[:200]
        self.ctx.data["typosquats"] = suspicious
        high = sum(1 for s in suspicious if s.get("score", 0) >= 40)
        self.result.stats.update({
            "live_dns": len(live_dns), "ct_recent": len(ct_recent),
            "urlscan_hits": len(urlscan_hits), "suspicious_high": high,
        })
        for s in suspicious:
            sc = s.get("score", 0)
            if sc >= 60:
                sev, conf = "critical", "medium"
            elif sc >= 40:
                sev, conf = "high", "medium"
            elif sc >= 30:
                sev, conf = "medium", "low"
            else:
                continue
            self.add("phishing_infra", sev, s["domain"],
                     evidence={"score": sc,
                               "signals": [k for k in
                                           ("in_dns", "in_ct", "in_urlscan",
                                            "mx", "phish_word") if s.get(k)]},
                     source="phishlab", status="candidate", confidence=conf)

    async def src_ct_recent(self, d):
        core = d.split(".")[0]
        cutoff = datetime.now(timezone.utc) - timedelta(days=90)
        try:
            j = await self.http.get_json(
                f"https://crt.sh/?q={quote('%' + core + '%')}&output=json",
                timeout=90)
        except Exception:
            return []
        out = []
        seen = set()
        for entry in (j or [])[:3000]:
            names = str(entry.get("common_name", "")) + "\n" + \
                    str(entry.get("name_value", ""))
            nb = entry.get("not_before", "")
            issued = None
            try:
                issued = datetime.fromisoformat(nb.replace("Z", "+00:00"))
            except Exception:
                pass
            for name in names.split("\n"):
                n = name.strip().lower().removeprefix("*.")
                if not n or n in seen:
                    continue
                seen.add(n)
                if core in n and d.lower() not in n and (
                        issued is None or issued >= cutoff):
                    out.append({"domain": n,
                                "issued": nb[:10],
                                "issuer": str(entry.get("issuer_name", ""))[:80]})
        return out[:100]

    async def src_urlscan(self, d):
        core = d.split(".")[0]
        try:
            j = await self.http.get_json(
                "https://urlscan.io/api/v1/search/",
                params={"q": f"page.domain:*{core}*", "size": 100}, timeout=30)
        except Exception:
            return []
        base_full = ".".join(d.split(".")[-2:])
        out = []
        for res in (j or {}).get("results", [])[:100]:
            page = res.get("page", {})
            dom = page.get("domain", "").lower()
            if dom and base_full not in dom and core in dom:
                out.append({"domain": dom, "url": page.get("url", ""),
                            "result": res.get("result", "")})
        return out
