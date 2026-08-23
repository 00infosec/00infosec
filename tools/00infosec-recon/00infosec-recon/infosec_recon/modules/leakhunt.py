from __future__ import annotations

import asyncio
import re

from .base import Module

EMAIL_RE = re.compile(r"[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}", re.I)
PASSWORD_LINE_RE = re.compile(
    r"([a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,})[:;|/\s]+(\S{4,80})", re.I)

GH_DORKS = [
    "{domain} password", "{domain} api_key", "{domain} secret",
    "{domain} token", "@{domain} password", 'filename:.env "{domain}"',
    'filename:.htpasswd "{domain}"', "filename:credentials \"{domain}\"",
    "{domain} aws_access_key_id", "{domain} client_secret",
]

DDG_QUERIES = [
    '"{d}" site:pastebin.com', '"{d}" site:rentry.co', '"@{d}" password',
    '"{d}" intext:password intext:email', '"{d}" "leaked" password',
]


class LeakHuntModule(Module):
    name = "leakhunt"
    description = "credential leaks: proxynova/HIBP/github dorks/pastes/ddg/intelx"
    provides = ("creds", "emails", "breaches")
    requires = ()

    async def run(self):
        d = self.ctx.domain
        creds, emails, breaches, pastes, gh_hits = {}, set(), [], [], []
        errors: dict[str, list] = {}

        async def safe(label, coro):
            try:
                await coro
            except Exception as e:
                errors.setdefault(label, []).append(str(e)[:100])

        tasks = [
            safe("proxynova", self.src_proxynova(d, creds, emails)),
            safe("hibp", self.src_hibp(d, breaches)),
            safe("psbdmp", self.src_psbdmp(d, pastes)),
            safe("ddg", self.src_ddg(d, creds, emails)),
        ]
        if self.cfg.gh_token:
            tasks.append(safe("github", self.src_github(d, gh_hits)))
        else:
            self.result.stats["github"] = "skipped (no GH_TOKEN)"
        await asyncio.gather(*tasks)

        cred_list = [{"email": e, "password": p, **meta} for (e, p), meta in creds.items()]
        email_list = sorted(emails | {c["email"] for c in cred_list})
        self.ctx.data["creds"] = cred_list
        self.ctx.data["emails"] = email_list
        self.ctx.data["breaches"] = breaches
        self.result.stats.update({
            "credentials": len(cred_list), "emails": len(email_list),
            "breaches": len(breaches), "pastes": len(pastes),
            "github_hits": len(gh_hits),
        })
        for c in cred_list:
            self.add("leaked_credential", "critical" if c["password"] else "high",
                     c["email"],
                     evidence={"password": c["password"][:12] + "..."},
                     source=c.get("source", ""), status="finding",
                     confidence="medium")
        for b in breaches:
            self.add("data_breach", "medium", d,
                     evidence={"breach": b.get("name"),
                               "accounts": b.get("count", 0),
                               "date": b.get("date")},
                     status="observation", confidence="high")
        for h in gh_hits[:40]:
            confirmed = h.get("confidence") == "confirmed"
            self.add("github_leak", "high" if confirmed else "medium", d,
                     evidence={"url": h.get("url", "")[:160],
                               "path": h.get("path", "")[:120]},
                     source="github",
                     status="finding" if confirmed else "candidate",
                     confidence="high" if confirmed else "medium")

    async def src_proxynova(self, d, creds, emails):
        j = await self.http.get_json(
            "https://api.proxynova.com/comb",
            params={"query": d, "limit": 50}, timeout=30)
        for line in (j or {}).get("lines", []):
            m = PASSWORD_LINE_RE.search(line)
            if m and d.lower() in m.group(1).lower():
                creds[(m.group(1).lower(), m.group(2))] = {"source": "proxynova"}
            else:
                for e in EMAIL_RE.findall(line):
                    if d.lower() in e.lower():
                        emails.add(e.lower())

    async def src_hibp(self, d, breaches):
        j = await self.http.get_json("https://haveibeenpwned.com/api/v3/breaches",
                                     timeout=45)
        dl = d.lower()
        for b in j or []:
            bd = (b.get("Domain") or "").lower()
            if not bd:
                continue
            if bd == dl or bd.endswith("." + dl) or dl.endswith("." + bd):
                breaches.append({"name": b.get("Name"), "count": b.get("PwnCount"),
                                 "date": b.get("BreachDate"), "source": "hibp"})

    async def src_psbdmp(self, d, pastes):
        from urllib.parse import quote
        j = await self.http.get_json(f"https://psbdmp.ws/api/search/{quote(d)}",
                                     timeout=30)
        items = (j or {}).get("data") or []
        if isinstance(items, dict):
            items = items.get("results", [])
        for it in items[:50]:
            pid = it.get("id") or it.get("paste_id")
            if pid:
                pastes.append({"source": "psbdmp",
                               "url": f"https://psbdmp.ws/api/dump/get/{pid}",
                               "snippet": str(it.get("title", ""))[:200]})

    async def src_ddg(self, d, creds, emails):
        try:
            from bs4 import BeautifulSoup
        except ImportError:
            self.result.stats["ddg"] = "skipped (no bs4)"
            return
        for q in DDG_QUERIES:
            query = q.format(d=d)
            try:
                r = await self.http.get(
                    "https://html.duckduckgo.com/html/", params={"q": query},
                    timeout=30, headers={"Accept": "text/html"})
                soup = BeautifulSoup(r.body, "html.parser")
                for a in soup.select("a.result__a")[:20]:
                    href = a.get("href", "")
                    title = a.get_text(strip=True)[:150]
                    if "uddg=" in href:
                        from urllib.parse import parse_qs, unquote, urlparse
                        qs = parse_qs(urlparse(href).query).get("uddg")
                        href = unquote(qs[0]) if qs else href
                    if any(x in href for x in ("pastebin.com", "rentry.co",
                                               "paste.ee", "psbdmp.ws")):
                        pastes_like = {"url": href, "snippet": title,
                                       "source": "ddg"}
                        self.ctx.data.setdefault("pastes", []).append(pastes_like)
            except Exception:
                pass
            await asyncio.sleep(2)

    async def src_github(self, d, gh_hits):
        token = self.cfg.gh_token
        headers = {"Authorization": f"Bearer {token}",
                   "Accept": "application/vnd.github.text-match+json"}
        for dork in GH_DORKS:
            try:
                j = await self.http.get_json(
                    "https://api.github.com/search/code",
                    params={"q": dork.format(domain=d), "per_page": 20},
                    headers=headers, timeout=30)
                items = (j or {}).get("items") or []
                for it in items:
                    repo = (it.get("repository") or {}).get("full_name", "")
                    path = it.get("path", "")
                    frag = ""
                    tms = it.get("text_matches") or []
                    if tms:
                        frag = tms[0].get("fragment", "")[:300]
                    hit = {"repo": repo, "path": path, "url": it.get("html_url", ""),
                           "snippet": frag, "confidence": "suspicious"}
                    raw = None
                    if repo and path:
                        try:
                            rr = await self.http.get(
                                f"https://raw.githubusercontent.com/{repo}/HEAD/{path}",
                                timeout=20, max_body=200_000,
                                headers={"Authorization": f"Bearer {token}"})
                            if rr.status == 200:
                                raw = rr.body
                        except Exception:
                            pass
                    if raw is not None:
                        confirmed = bool(re.search(
                            r"(AKIA[0-9A-Z]{16}|-----BEGIN [A-Z ]*PRIVATE KEY-----"
                            r"|ghp_[0-9a-zA-Z]{36}|sk_live_[A-Za-z0-9]{24,})", raw))
                        has_pair = any(
                            m and d.lower() in m.group(1).lower() and len(m.group(2)) >= 6
                            for m in (PASSWORD_LINE_RE.search(raw),))
                        hit["confidence"] = ("confirmed" if confirmed
                                             else "suspicious" if has_pair
                                             else "weak")
                    if hit["confidence"] != "weak":
                        gh_hits.append(hit)
            except Exception:
                pass
            await asyncio.sleep(2.5)
