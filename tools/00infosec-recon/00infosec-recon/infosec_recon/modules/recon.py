from __future__ import annotations

import asyncio
import json
import re
import time
from urllib.parse import quote

from .base import Module


def _src(name):
    def deco(fn):
        fn._source = name
        return fn
    return deco


class ReconModule(Module):
    name = "recon"
    description = "passive subdomain enum + dns + http probe + stack + takeover"
    provides = ("subdomains", "hosts_alive", "urls", "http_records", "stack",
                "internetdb", "rdap")
    requires = ()

    VERSION_FILES = [
        ("/package.json", "package_json"), ("/composer.json", "composer_json"),
        ("/CHANGELOG.txt", "changelog"), ("/readme.html", "readme_html"),
        ("/.git/config", "git_config"), ("/.env", "dotenv"),
        ("/swagger.json", "swagger_json"), ("/api/swagger.json", "api_swagger"),
        ("/openapi.json", "openapi_json"),
    ]

    TAKEOVER_SIGS = [
        ("GitHub Pages", r"\.github\.io$", r"There isn't a GitHub Pages site here|404.{0,10}File not found"),
        ("AWS S3", r"s3[.-].*amazonaws\.com$|\.s3\.amazonaws\.com$", r"NoSuchBucket|The specified bucket does not exist"),
        ("Heroku", r"\.herokudns\.com$|\.herokuapp\.com$", r"No such app|herokucdn\.com/error-pages/no-such-app"),
        ("Azure", r"\.azurewebsites\.net$|\.cloudapp\.net$|\.trafficmanager\.net$", r"404 Web Site not found"),
        ("Fastly", r"\.fastly\.net$", r"Fastly error: unknown domain"),
        ("Shopify", r"\.myshopify\.com$", r"Sorry, this shop is currently unavailable"),
        ("Bitbucket", r"\.bitbucket\.io$", r"Repository not found"),
        ("Surge.sh", r"\.surge\.sh$", r"project not found"),
        ("Pantheon", r"\.pantheonsite\.io$", r"The gods are wise"),
        ("Zendesk", r"\.zendesk\.com$", r"Help Center Closed"),
        ("Tumblr", r"\.domains\.tumblr\.com$", r"Whatever you were looking for doesn't currently exist"),
    ]

    STACK_SIGS = {
        "nginx": ("server", "web-server", r"nginx(?:/([\d.]+))?"),
        "apache": ("server", "web-server", r"apache(?:/([\d.]+))?"),
        "tomcat": ("server", "app-server", r"(?:Apache-Coyote|Tomcat)(?:/([\d.]+))?"),
        "iis": ("server", "web-server", r"Microsoft-IIS(?:/([\d.]+))?"),
        "litespeed": ("server", "web-server", r"LiteSpeed"),
        "caddy": ("server", "web-server", r"Caddy"),
        "cloudflare": ("header", "cdn", r"cloudflare|cf-ray|__cfduid"),
        "php": ("header", "language", r"PHP(?:/([\d.]+))?|PHPSESSID"),
        "asp.net": ("header", "framework", r"ASP\.NET|X-AspNet-Version"),
        "express": ("header", "framework", r"^Express$"),
        "next.js": ("html", "frontend", r"/_next/static|__NEXT_DATA__"),
        "react": ("html", "frontend", r"data-reactroot|react\.production|_reactListening"),
        "vue.js": ("html", "frontend", r"vue\.runtime|__VUE_HMR_RUNTIME__|id=\"app\" data-v-"),
        "angular": ("html", "frontend", r"ng-version=\"([\d.]+)\"|angular\.min"),
        "jquery": ("html", "library", r"jquery[.-]([\d.]+)"),
        "wordpress": ("html", "cms", r"wp-content/(?:themes|plugins)|wp-json"),
        "drupal": ("html", "cms", r"Drupal\.settings|sites/default/files"),
        "joomla": ("meta", "cms", r"Joomla!?\s*([\d.]+)?"),
        "shopify": ("html", "ecommerce", r"cdn\.shopify\.com|Shopify\.theme"),
        "vercel": ("header", "hosting", r"x-vercel-id|x-vercel-cache|^Vercel$"),
        "netlify": ("header", "hosting", r"^Netlify|x-nf-request-id"),
        "gunicorn": ("server", "language", r"gunicorn(?:/([\d.]+))?"),
        "django": ("cookie", "framework", r"csrftoken|django_language"),
        "laravel": ("cookie", "framework", r"laravel_session"),
        "spring": ("cookie", "framework", r"JSESSIONID"),
    }

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.per_source: dict[str, set] = {}
        self.errors: dict[str, list] = {}
        self.skipped_sources: dict[str, str] = {}

    async def run(self):
        d = self.ctx.domain
        deep = getattr(self.ctx.args, "deep", False)
        passive = bool(getattr(self.ctx.args, "passive", False))
        self.result.stats["mode"] = "passive" if passive else \
            ("deep" if deep else "standard")

        await self.passive_enum(d)
        subs = self.all_subdomains()
        self.ctx.key_list("subdomains").update(subs)

        if not self.dns.available and not subs:
            raise RuntimeError("no subdomains found and no resolver available")

        wc = {"ips": set(), "cnames": set(), "is_wildcard": False}
        if self.dns.available:
            wc = await self.dns.detect_wildcard(d)
            if wc["is_wildcard"]:
                self.result.stats["wildcard"] = True

        to_resolve = sorted(subs | {d})
        resolved = []
        alive = []
        if self.dns.available:
            brute = self.brute_candidates(d) if deep else {f"www.{d}"}
            permute = self.permute_candidates(subs) if deep else set()
            to_resolve = sorted(set(to_resolve) | brute | permute)
            if not passive:
                self.console.print(f"[muted]resolving {len(to_resolve)} hosts...[/muted]")
            dns_started = time.monotonic()

            def dns_progress(done: int, total: int) -> None:
                elapsed = max(time.monotonic() - dns_started, 0.001)
                eta = int((total - done) / (done / elapsed))
                minutes, seconds = divmod(eta, 60)
                self.result.stats["dns"] = (
                    f"{done}/{total} ({done * 100 // total}%) ETA {minutes:02d}:{seconds:02d}"
                )

            resolved = await self.dns.resolve_many(
                to_resolve, on_progress=dns_progress)
            alive = [r["host"] for r in resolved
                     if r["alive"] and not self.dns.is_wildcard_hit(r, wc)]
            for r in resolved:
                if r["alive"] and self.dns.is_wildcard_hit(r, wc):
                    r["wildcard_fp"] = True
            brute_alive = {r["host"] for r in resolved if r["alive"] and r["host"] in brute}
            permute_alive = {r["host"] for r in resolved if r["alive"] and r["host"] in permute}
            if brute_alive:
                self.per_source["dns-brute"] = brute_alive
            if permute_alive:
                self.per_source["dns-permute"] = permute_alive
        else:
            alive = list(subs)[:100]

        self.ctx.data["dns_records"] = resolved
        self.ctx.key_list("hosts_alive").update(alive)
        self.result.stats["subdomains"] = len(subs)
        self.result.stats["alive"] = len(alive)

        records = [] if passive else await self.probe_hosts(sorted(alive))
        self.ctx.data["http_records"] = [
            {"host": r.host, "url": r.url, "status": r.status, "title": r.title,
             "scheme": r.scheme, "server": r.server, "stack": r.stack,
             "content_length": r.content_length, "exposed_files": r.exposed_files}
            for r in records]
        self.ctx.data["stack"] = {r.host: r.stack for r in records if r.stack}

        stack_techs = set()
        for st in self.ctx.data["stack"].values():
            stack_techs.update(st.keys())
        self.result.stats["techs"] = len(stack_techs)

        exposed = [(r.host, ef) for r in records for ef in r.exposed_files]
        for host, ef in exposed:
            sev = "critical" if any(x in ef["path"] for x in ("/.env", "/.git/", ".sql")) else "high"
            self.add("exposed_file", sev, host,
                     evidence={"path": ef["path"], "validator": "http200"},
                     source="probe", status="candidate", confidence="medium")
        self.result.stats["exposed_files"] = len(exposed)

        if deep and not passive:
            await self.takeover_checks(resolved)
        if passive:
            self.ctx.data["internetdb"] = {}
            self.ctx.data["rdap"] = {}
        else:
            await self.internetdb_enrich(alive_resolved=[r for r in resolved if r["A"]])
            await self.rdap_lookup()

        self.result.stats["by_source"] = {k: len(v) for k, v in self.per_source.items()}
        self._publish_source_status()

    # ------------------------------------------------------------------ sources

    def all_subdomains(self) -> set:
        out = set()
        for s in self.per_source.values():
            out.update(s)
        return out

    KEY_ENV = {
        "virustotal": "VT_API_KEY", "securitytrails": "ST_API_KEY",
        "chaos": "CHAOS_API_KEY", "shodan": "SHODAN_API_KEY",
        "binaryedge": "BE_API_KEY", "leakix": "LEAKIX_API_KEY",
    }

    async def passive_enum(self, domain: str):
        keyed_needed = {}
        tasks = {}
        for attr in dir(self):
            fn = getattr(self, attr)
            if callable(fn) and hasattr(fn, "_source"):
                name = fn._source
                if name in self.KEY_ENV:
                    import os
                    if not (os.environ.get(self.KEY_ENV[name])
                            or getattr(self.cfg, {
                                "VT_API_KEY": "vt_key",
                                "ST_API_KEY": "st_key",
                                "CHAOS_API_KEY": "chaos_key",
                                "SHODAN_API_KEY": "shodan_key",
                                "BE_API_KEY": "be_key",
                                "LEAKIX_API_KEY": "leakix_key",
                            }[self.KEY_ENV[name]], None)):
                        keyed_needed[name] = f"key ausente ({self.KEY_ENV[name]})"
                        continue
                tasks[name] = asyncio.create_task(
                    self._run_source(name, fn, domain))

        for fut in asyncio.as_completed(tasks.values()):
            try:
                await fut
            except Exception:
                pass
        self.skipped_sources = keyed_needed
        self.result.stats["sources_active"] = sum(
            1 for v in self.per_source.values() if v)

    def _publish_source_status(self):
        srcs = dict(self.skipped_sources)
        for name, errs in self.errors.items():
            srcs[name] = f"error: {errs[0][:60]}"
        for name, hosts in self.per_source.items():
            srcs.setdefault(name, f"ok ({len(hosts)} hosts)")
        self.result.stats["sources"] = srcs

    async def _run_source(self, name, fn, domain):
        try:
            found = await fn(domain)
            self.per_source.setdefault(name, set()).update(found or ())
        except Exception as e:
            self.errors.setdefault(name, []).append(str(e)[:120])

    @_src("crtsh")
    async def src_crtsh(self, d):
        j = await self.http.get_json(
            f"https://crt.sh/?q=%.{quote(d)}&output=json", timeout=90)
        out = set()
        for entry in j or []:
            for field in ("name_value", "common_name"):
                for line in str(entry.get(field, "")).replace("\\n", "\n").split("\n"):
                    from ..core.net import normalize_host
                    h = normalize_host(line.strip(), d)
                    if h:
                        out.add(h)
        return out

    @_src("crtname")
    async def src_crtname(self, d):
        r = await self.http.get(f"https://crt.name/v1/search?apex={quote(d)}", timeout=45)
        out = set()
        try:
            j = json.loads(r.body)
            items = j.get("results") or j.get("data") or []
            if isinstance(items, list):
                for it in items:
                    name = it if isinstance(it, str) else (
                        it.get("name") or it.get("common_name") or "")
                    from ..core.net import normalize_host
                    h = normalize_host(str(name), d)
                    if h:
                        out.add(h)
        except Exception:
            out.update(_extract_hosts(r.body, d))
        return out

    @_src("otx")
    async def src_otx(self, d):
        out = set()
        j = await self.http.get_json(
            f"https://otx.alienvault.com/api/v1/indicators/domain/{d}/passive_dns",
            timeout=45)
        for e in (j or {}).get("passive_dns", []):
            from ..core.net import normalize_host
            h = normalize_host(e.get("hostname", ""), d)
            if h:
                out.add(h)
        urls = self.ctx.key_list("urls")
        j2 = await self.http.get_json(
            f"https://otx.alienvault.com/api/v1/indicators/domain/{d}/url_list?limit=500",
            timeout=45)
        for e in (j2 or {}).get("url_list", [])[:500]:
            u = e.get("url")
            if u:
                urls.add(u)
        return out

    @_src("hackertarget")
    async def src_hackertarget(self, d):
        r = await self.http.get(f"https://api.hackertarget.com/hostsearch/?q={d}",
                                timeout=30)
        out = set()
        from ..core.net import normalize_host
        for line in r.body.splitlines():
            host = line.split(",")[0].strip()
            h = normalize_host(host, d)
            if h:
                out.add(h)
        return out

    @_src("rapiddns")
    async def src_rapiddns(self, d):
        r = await self.http.get(f"https://rapiddns.io/subdomain/{d}?full=1", timeout=45)
        return _extract_hosts(r.body, d)

    @_src("anubis")
    async def src_anubis(self, d):
        j = await self.http.get_json(f"https://jldc.me/anubis/subdomains/{d}", timeout=45)
        from ..core.net import normalize_host
        out = set()
        for x in j or []:
            h = normalize_host(str(x), d)
            if h:
                out.add(h)
        return out

    @_src("urlscan")
    async def src_urlscan(self, d):
        j = await self.http.get_json(
            f"https://urlscan.io/api/v1/search/?q=domain:{d}&size=1000", timeout=45)
        out = set()
        urls = self.ctx.key_list("urls")
        from ..core.net import normalize_host
        for res in (j or {}).get("results", []):
            page = res.get("page", {})
            h = normalize_host(page.get("domain", ""), d)
            if h:
                out.add(h)
            u = page.get("url")
            if u and d in u:
                urls.add(u)
        return out

    @_src("threatminer")
    async def src_threatminer(self, d):
        j = await self.http.get_json(
            f"https://api.threatminer.org/v2/domain.php?q={d}&rt=5", timeout=30)
        from ..core.net import normalize_host
        out = set()
        for x in (j or {}).get("results", []):
            h = normalize_host(str(x), d)
            if h:
                out.add(h)
        return out

    @_src("wayback")
    async def src_wayback(self, d):
        r = await self.http.get(
            f"http://web.archive.org/cdx/search/cdx?url=*.{d}/*&output=text"
            f"&fl=original&collapse=urlkey&limit=20000", timeout=120)
        urls = self.ctx.key_list("urls")
        from ..core.net import normalize_host
        out = set()
        for line in r.body.splitlines():
            u = line.strip()
            if not u.startswith(("http://", "https://")):
                continue
            urls.add(u)
            from urllib.parse import urlparse
            try:
                h = normalize_host(urlparse(u).hostname or "", d)
                if h:
                    out.add(h)
            except Exception:
                pass
        return out

    @_src("subdomaincenter")
    async def src_subdomaincenter(self, d):
        j = await self.http.get_json(f"https://api.subdomain.center/?domain={d}",
                                     timeout=45)
        from ..core.net import normalize_host
        out = set()
        for x in j or []:
            h = normalize_host(str(x), d)
            if h:
                out.add(h)
        return out

    @_src("dnsrepo")
    async def src_dnsrepo(self, d):
        r = await self.http.get(f"https://dnsrepo.noc.org/?search={d}&limit=1000",
                                timeout=30)
        return _extract_hosts(r.body, d)

    @_src("riddler")
    async def src_riddler(self, d):
        r = await self.http.get(f"https://riddler.io/search?q=pld:{d}", timeout=20)
        return _extract_hosts(r.body, d)

    @_src("virustotal")
    async def src_virustotal(self, d):
        out = set()
        cursor = None
        from ..core.net import normalize_host
        for _ in range(8):
            url = f"https://www.virustotal.com/api/v3/domains/{d}/subdomains?limit=40"
            if cursor:
                url += f"&cursor={cursor}"
            j = await self.http.get_json(url, headers={"x-apikey": self.cfg.vt_key},
                                         timeout=45)
            for item in (j or {}).get("data", []):
                h = normalize_host(item.get("id", ""), d)
                if h:
                    out.add(h)
            cursor = ((j or {}).get("meta") or {}).get("cursor")
            if not cursor:
                break
        return out

    @_src("securitytrails")
    async def src_securitytrails(self, d):
        j = await self.http.get_json(
            f"https://api.securitytrails.com/v1/domain/{d}/subdomains?children_only=false",
            headers={"APIKEY": self.cfg.st_key}, timeout=45)
        return {f"{s}.{d}" for s in (j or {}).get("subdomains", [])}

    @_src("chaos")
    async def src_chaos(self, d):
        j = await self.http.get_json(
            f"https://dns.projectdiscovery.io/dns/{d}/subdomains",
            headers={"Authorization": self.cfg.chaos_key}, timeout=30)
        subs = (j or {}).get("subdomains", [])
        return {(f"{s}.{d}" if s else d) for s in subs}

    @_src("shodan")
    async def src_shodan(self, d):
        j = await self.http.get_json(
            f"https://api.shodan.io/dns/domain/{d}?key={self.cfg.shodan_key}",
            timeout=30)
        return {f"{s}.{d}" for s in (j or {}).get("subdomains", [])}

    @_src("binaryedge")
    async def src_binaryedge(self, d):
        j = await self.http.get_json(
            f"https://api.binaryedge.io/v2/query/domains/subdomain/{d}",
            headers={"X-Key": self.cfg.be_key}, timeout=30)
        return set((j or {}).get("events", []))

    @_src("leakix")
    async def src_leakix(self, d):
        j = await self.http.get_json(
            f"https://leakix.net/api/subdomains/{d}",
            headers={"api-key": self.cfg.leakix_key, "Accept": "application/json"},
            timeout=30)
        from ..core.net import normalize_host
        out = set()
        for e in j or []:
            h = normalize_host(e.get("subdomain", ""), d)
            if h:
                out.add(h)
        return out

    # ------------------------------------------------------------------ expand

    BRUTE_WORDS = [
        "www", "mail", "smtp", "vpn", "sso", "api", "dev", "hml", "homolog", "prod",
        "admin", "portal", "app", "web", "intranet", "extranet", "db", "mysql",
        "postgres", "redis", "git", "jenkins", "jira", "confluence", "grafana",
        "kibana", "k8s", "rancher", "remote", "rdp", "ftp", "sftp", "files", "cdn",
        "static", "assets", "img", "media", "video", "download", "downloads", "docs",
        "wiki", "blog", "shop", "store", "pay", "pagamento", "pix", "boleto",
        "cartao", "internet", "banking", "mobile", "m", "api2", "v2", "beta", "test",
        "qa", "staging", "stg", "uat", "old", "new", "backup", "bkp", "auth", "login",
        "id", "oauth", "token", "gateway", "ws", "socket", "chat", "mail2", "mx",
        "ns1", "ns2", "cloud", "aws", "azure", "gcp", "sap", "erp", "crm", "bi",
    ]

    def brute_candidates(self, d) -> set:
        return {f"{w}.{d}" for w in self.BRUTE_WORDS}

    PERMUTE_AFFIXES = ["dev", "hml", "homolog", "uat", "qa", "stg", "staging",
                       "test", "prod", "old", "new", "2", "02", "v2", "beta",
                       "sandbox", "int", "ext", "bkp", "backup"]

    def permute_candidates(self, subs, cap: int = 3000) -> set:
        firsts = {s.split(".")[0] for s in subs}
        out = set()
        base = self.ctx.domain
        for f in list(firsts)[:150]:
            for a in self.PERMUTE_AFFIXES:
                out.update({f"{a}-{f}.{base}", f"{f}-{a}.{base}",
                            f"{a}{f}.{base}", f"{f}{a}.{base}"})
        return set(list(out))[:cap]

    # ------------------------------------------------------------------ probe

    async def probe_hosts(self, hosts):
        cap = int(getattr(self.ctx.args, "max_probe_hosts", 400) or 400)
        ordered = sorted(
            hosts,
            key=lambda h: (h != self.ctx.domain, h != f"www.{self.ctx.domain}", h),
        )
        skipped = len(ordered) - cap
        if skipped > 0:
            self.console.print(
                f"[warn]probe limitado a {cap} hosts "
                f"({skipped} ficaram de fora — ajuste com --max-probe-hosts)[/warn]")
            self.result.stats["probe_skipped"] = skipped
            ordered = ordered[:cap]
        sem = asyncio.Semaphore(25)
        results = []

        async def one(h):
            async with sem:
                rec = await self.probe_one(h)
                if rec:
                    results.append(rec)

        await asyncio.gather(*(one(h) for h in ordered),
                             return_exceptions=True)
        return results

    async def probe_one(self, host):
        for scheme in ("https", "http"):
            url = f"{scheme}://{host}/"
            try:
                r = await self.http.probe_url(url, timeout=10, max_body=200_000,
                                              scoped=True)
            except Exception:
                continue
            rec = make_http_record(host, r, scheme)
            await self.fingerprint(rec, r, url)
            return rec
        return None

    async def fingerprint(self, rec, r, base_url):
        body = (r.body or "")[:200_000]
        headers = r.headers or {}
        cookies = "; ".join(r.cookies or [])
        stack = {}
        for tech, (where, cat, pat) in self.STACK_SIGS.items():
            ver = None
            hit = False
            try:
                rx = re.compile(pat, re.I)
                if where == "server":
                    m = rx.search(headers.get("server", ""))
                elif where == "header":
                    m = rx.search(json.dumps(headers))
                elif where == "cookie":
                    m = rx.search(cookies)
                else:
                    m = rx.search(body)
                if m:
                    hit = True
                    if m.groups():
                        ver = next((g for g in m.groups() if g), None)
            except Exception:
                continue
            if hit:
                stack[tech] = {"category": cat, "version": ver}
        server = headers.get("server", "")
        for tech, (cat, pat) in {
            "nginx": ("web-server", r"nginx(?:/([\d.]+))?"),
            "iis": ("web-server", r"Microsoft-IIS(?:/([\d.]+))?"),
            "apache": ("web-server", r"Apache(?:/([\d.]+))?"),
        }.items():
            if tech not in stack and server:
                m = re.search(pat, server, re.I)
                if m:
                    stack[tech] = {"category": cat, "version": m.group(1)}
        exposed = []
        for path, name in self.VERSION_FILES:
            try:
                fr = await self.http.request("GET", base_url.rstrip("/") + path,
                                             timeout=6, allow_redirects=False,
                                             max_body=8000, scoped=True)
            except Exception:
                continue
            if fr.status == 200 and fr.body:
                exposed.append({"path": path, "exposed": True})
                if path == "/package.json":
                    try:
                        pj = json.loads(fr.body)
                        v = pj.get("version")
                        if v:
                            stack[f"app:{pj.get('name', 'package')}"] = {
                                "category": "application", "version": str(v)}
                        for dep, dv in list((pj.get("dependencies") or {}).items())[:40]:
                            stack.setdefault(f"npm:{dep}", {
                                "category": "JavaScript library",
                                "version": str(dv).lstrip("^~>=< ")})
                    except Exception:
                        pass
        rec.exposed_files = exposed
        rec.stack = stack
        for t, meta in stack.items():
            if t == "cloudflare":
                rec.waf.append({"name": "Cloudflare", "kind": "waf/cdn"})
        missing = [h for h in ("strict-transport-security", "content-security-policy",
                               "x-frame-options", "x-content-type-options")
                   if h not in (r.headers or {})]
        rec.security_missing = missing

    # ------------------------------------------------------------------ takeover

    async def takeover_checks(self, resolved):
        cands = [(r["host"], r["CNAME"]) for r in resolved
                 if r.get("alive") and r.get("CNAME")]
        if not cands:
            return
        vulns = 0
        for host, cnames in cands:
            service = None
            sig = None
            for svc, cre, bre in self.TAKEOVER_SIGS:
                if any(re.search(cre, c.lower()) for c in cnames):
                    service, sig = svc, bre
                    break
            if not service:
                continue
            body = ""
            for scheme in ("https", "http"):
                try:
                    rr = await self.http.probe_url(f"{scheme}://{host}/",
                                                   timeout=8, max_body=60_000,
                                                   scoped=True)
                    body = rr.body
                    break
                except Exception:
                    continue
            vulnerable = bool(service and sig and re.search(sig, body or "", re.I))
            if vulnerable:
                vulns += 1
                self.add("subdomain_takeover", "critical", host,
                         evidence={"cname": cnames[0], "service": service},
                         source="takeover", status="finding",
                         confidence="high")
        self.result.stats["takeover_vuln"] = vulns

    # ------------------------------------------------------- internetdb + rdap

    async def internetdb_enrich(self, alive_resolved):
        ips = []
        seen = set()
        for r in alive_resolved:
            for ip in r.get("A", []):
                if ip not in seen:
                    seen.add(ip)
                    ips.append(ip)
        if not ips:
            return
        sem = asyncio.Semaphore(12)
        db = {}

        async def one(ip):
            async with sem:
                try:
                    j = await self.http.get_json(f"https://internetdb.shodan.io/{ip}",
                                                 timeout=15)
                    if j and not j.get("detail"):
                        db[ip] = j
                        for port in j.get("ports", []) or []:
                            if port in (80, 443, 8080, 8443):
                                continue
                            self.add("open_port", "low", ip,
                                     evidence=f"port {port}/tcp",
                                     source="internetdb", status="observation",
                                     confidence="high")
                        for cve in (j.get("vulns") or [])[:50]:
                            self.add("internetdb_cve", "high", ip,
                                     evidence={"cve": cve,
                                               "note": "sem correlação de produto/versão"},
                                     source="internetdb",
                                     status="candidate", confidence="low")
                except Exception:
                    pass

        await asyncio.gather(*(one(ip) for ip in ips[:64]))
        self.ctx.data["internetdb"] = db
        self.result.stats["internetdb_ips"] = len(db)

    async def rdap_lookup(self):
        try:
            j = await self.http.get_json(f"https://rdap.org/domain/{self.ctx.domain}",
                                         timeout=20)
            slim = {}
            if isinstance(j, dict):
                events = {e.get("eventAction"): e.get("eventDate")
                          for e in j.get("events", []) or []}
                entities = []
                for ent in j.get("entities", []) or []:
                    roles = ",".join(ent.get("roles", []))
                    name = ""
                    v = ent.get("vcardArray")
                    if v and len(v) > 1:
                        for item in v[1]:
                            if item and item[0] == "fn":
                                name = item[3]
                                break
                    if roles:
                        entities.append({"roles": roles, "name": name})
                slim = {"registrar": next((e["name"] for e in entities
                                           if "registrar" in e["roles"]), ""),
                        "created": events.get("registration"),
                        "expires": events.get("expiration"),
                        "changed": events.get("last changed"),
                        "nameservers": [ns.get("ldhName", "")
                                        for ns in j.get("nameservers", [])],
                        "status": j.get("status", []),
                        "entities": entities[:5]}
            self.ctx.data["rdap"] = slim
            self.result.stats["rdap"] = bool(slim)
        except Exception:
            self.ctx.data["rdap"] = {}


def make_http_record(host: str, r, scheme: str):
    from ..core.models import HttpRecord
    title = ""
    tm = re.search(r"<title[^>]*>(.*?)</title>", r.body or "", re.I | re.S)
    if tm:
        title = re.sub(r"\s+", " ", tm.group(1)).strip()[:120]
    return HttpRecord(
        host=host, url=f"{scheme}://{host}/",
        status=r.status, title=title, scheme=scheme,
        server=(r.headers or {}).get("server", ""),
        content_length=r.content_length,
    )


def _extract_hosts(text: str, d: str) -> set:
    from ..core.net import extract_hosts_from_text
    return extract_hosts_from_text(text or "", d)
