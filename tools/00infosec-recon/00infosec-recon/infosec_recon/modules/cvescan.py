from __future__ import annotations

import asyncio
import json
import re
from urllib.parse import quote

from .base import Module

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_API = "https://api.first.org/data/v1/epss"
CIRCL_API = "https://cve.circl.lu/api"
OSV_API = "https://api.osv.dev/v1/query"
GHSA_API = "https://api.github.com/advisories"
EXPLOITDB_CSV = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"

STACK_CPE_MAP = {
    "nginx": ("nginx", "nginx"), "apache": ("apache", "http_server"),
    "iis": ("microsoft", "internet_information_server"),
    "litespeed": ("litespeed_technologies", "openlitespeed"),
    "caddy": ("caddyserver", "caddy"), "tomcat": ("apache", "tomcat"),
    "jetty": ("eclipse", "jetty"), "lighttpd": ("lighttpd", "lighttpd"),
    "php": ("php", "php"), "node.js": ("nodejs", "node.js"),
    "next.js": ("vercel", "next.js"), "express": ("openjsf", "express"),
    "django": ("djangoproject", "django"), "flask": ("palletsprojects", "flask"),
    "rails": ("rubyonrails", "rails"), "laravel": ("laravel", "laravel"),
    "spring": ("vmware", "spring_framework"), "spring boot": ("vmware", "spring_boot"),
    "asp.net": ("microsoft", "asp.net"), "wordpress": ("wordpress", "wordpress"),
    "drupal": ("drupal", "drupal"), "joomla": ("joomla", "joomla!"),
    "mysql": ("oracle", "mysql"), "mariadb": ("mariadb", "mariadb"),
    "postgresql": ("postgresql", "postgresql"), "mongodb": ("mongodb", "mongodb"),
    "redis": ("redis", "redis"), "elasticsearch": ("elastic", "elasticsearch"),
    "weblogic": ("oracle", "weblogic_server"), "jenkins": ("jenkins", "jenkins"),
    "gitlab": ("gitlab", "gitlab"), "openssl": ("openssl", "openssl"),
}

OSV_ECOSYSTEM_MAP = {
    "node.js": "npm", "next.js": "npm", "react": "npm", "vue.js": "npm",
    "angular": "npm", "express": "npm", "jquery": "npm",
    "django": "PyPI", "flask": "PyPI", "laravel": "Packagist",
    "spring": "Maven", "spring boot": "Maven",
}


class CveScanModule(Module):
    name = "cvescan"
    description = "CVE intel: NVD/CIRCL/OSV/GHSA + KEV + EPSS + ExploitDB"
    provides = ("cves",)
    requires = ("stack",)

    async def run(self):
        stack = self.ctx.data.get("stack") or {}
        hits = self.stack_to_products(stack)
        self.result.stats["stack_hits"] = len(hits)
        if not hits:
            self.console.print("[warn]no stack hits - cvescan will run KEV/EPSS only[/warn]")

        cves: dict[str, dict] = {}
        kev_meta, exploitdb = {}, {}
        errors: dict[str, list] = {}

        async def collect(label, coro):
            try:
                items = await coro
                for it in items or []:
                    cid = it["id"].upper()
                    if cid not in cves:
                        cves[cid] = {**it, "sources": [label]}
                    else:
                        ex = cves[cid]
                        for k, v in it.items():
                            if v and not ex.get(k):
                                ex[k] = v
                        if label not in ex["sources"]:
                            ex["sources"].append(label)
            except Exception as e:
                errors.setdefault(label.split(":")[0], []).append(str(e)[:100])

        # KEV is enrichment only.  It must never add the entire CISA catalog
        # to ``cves``: source collectors below are the product-scoped input.
        async def collect_kev():
            try:
                await self.src_kev(kev_meta)
            except Exception as e:
                errors.setdefault("cisa", []).append(str(e)[:100])

        tasks = [collect_kev(), collect("exploitdb", self.src_exploitdb(exploitdb))]
        nvd_counts: dict[tuple, int] = {}
        for h in hits:
            vendor, product = h["vendor"], h["product"]

            async def _nvd_counted(v=vendor, p=product, ver=h["version"]):
                items = await self.nvd_by_cpe(v, p, ver)
                nvd_counts[(v, p)] = len(items)
                return items

            tasks.append(collect(f"nvd:{vendor}:{product}", _nvd_counted()))
            tasks.append(collect(f"circl:{vendor}:{product}",
                                 self.src_circl(vendor, product)))
            eco = OSV_ECOSYSTEM_MAP.get(h["tech"].lower())
            if eco:
                tasks.append(collect(f"osv:{eco}:{product}",
                                     self.src_osv(product, eco)))
        gh_ecos = {OSV_ECOSYSTEM_MAP[h["tech"].lower()] for h in hits
                   if h["tech"].lower() in OSV_ECOSYSTEM_MAP}
        if self.cfg.gh_token:
            for eco in list(gh_ecos)[:3]:
                tasks.append(collect(f"ghsa:{eco}", self.src_ghsa(eco)))

        await asyncio.gather(*tasks)

        empty = [(h, (h["vendor"], h["product"])) for h in hits
                 if nvd_counts.get((h["vendor"], h["product"]), 0) == 0]
        if empty and not getattr(self.ctx.args, "quick_nvd", False):
            wave2 = []
            for h, key in empty[:3]:
                wave2.append(collect(
                    f"nvd-kw:{h['product']}",
                    self.nvd_by_keyword(h["product"])))
            await asyncio.gather(*wave2)

        # Keep only CVEs that can be tied back to a discovered product/host.
        # This also bounds EPSS queries to relevant CVEs rather than the KEV
        # catalog (which may contain thousands of unrelated entries).
        host_map = self.correlate(cves, hits) if hits else {}
        cves = {cid: c for cid, c in cves.items() if c.get("matched_hosts")}

        epss = {}
        if cves:
            try:
                epss = await self.src_epss(list(cves.keys()))
            except Exception as e:
                errors.setdefault("epss", []).append(str(e)[:100])

        for cid, c in cves.items():
            meta = kev_meta.get(cid)
            c["kev"] = bool(meta)
            if meta:
                c["kev_meta"] = meta
            e = epss.get(cid)
            if e:
                c["epss_score"] = e["score"]
            c["exploitdb_ids"] = exploitdb.get(cid, [])
            score = c.get("cvss")
            from ..core.models import severity_from_cvss
            c["severity"] = severity_from_cvss(score)
            c["exploitable"] = bool(c["exploitdb_ids"] or c["kev"])

        ordered = sorted(cves.values(),
                         key=lambda c: (not c.get("kev"), -(c.get("cvss") or 0)))
        self.ctx.data["cves"] = ordered
        self.ctx.data["cve_by_host"] = {h: sorted(ids) for h, ids in host_map.items()}

        self.emit_findings(ordered)

        crit = sum(1 for c in ordered if (c.get("cvss") or 0) >= 9)
        kev_n = sum(1 for c in ordered if c["kev"])
        correlated = sum(1 for c in ordered if c.get("matched_hosts"))
        self.result.stats.update({"cves": len(ordered),
                                  "cves_correlated": correlated,
                                  "kev": kev_n, "critical": crit,
                                  "exploitable": sum(
                                      1 for c in ordered if c["exploitable"])})
        for label, errs in errors.items():
            if errs:
                self.result.stats.setdefault("sources", {})[label] = \
                    {"status": "error", "detail": errs[0][:80]}

    def stack_to_products(self, stack):
        seen = {}
        for host, techs in (stack or {}).items():
            for tech_name, info in techs.items():
                key = tech_name.lower().strip()
                mapped = STACK_CPE_MAP.get(key)
                if key.startswith(("npm:", "app:")):
                    continue
                if not mapped and isinstance(info, dict):
                    cpe = info.get("cpe")
                    if isinstance(cpe, str) and ":" in cpe:
                        mapped = tuple(cpe.split(":", 1))
                if not mapped:
                    continue
                k = (mapped[0], mapped[1], info.get("version"))
                if k not in seen:
                    seen[k] = {"vendor": mapped[0], "product": mapped[1],
                               "version": info.get("version"), "tech": tech_name,
                               "hosts": set()}
                seen[k]["hosts"].add(host)
        out = []
        for v in seen.values():
            v["hosts"] = sorted(v["hosts"])
            out.append(v)
        return out

    async def nvd_by_cpe(self, vendor, product, version=None):
        delay = 0.6 if self.cfg.nvd_key else 6.5
        headers = {"apiKey": self.cfg.nvd_key} if self.cfg.nvd_key else None
        base_ver = version or "*"
        cpe = f"cpe:2.3:a:{vendor}:{product}:{base_ver}:*:*:*:*:*:*:*"
        params = {"cpeName": cpe, "isVulnerable": ""} if version else \
                 {"virtualMatchString": f"cpe:2.3:a:{vendor}:{product}:*:*:*:*:*:*:*:*"}
        out = []
        start = 0
        for _ in range(4):
            p = {**params, "resultsPerPage": 2000, "startIndex": start}
            j = await self.http.get_json(NVD_API, params=p, headers=headers,
                                         timeout=120)
            vulns = (j or {}).get("vulnerabilities") or []
            for v in vulns:
                parsed = parse_nvd(v.get("cve") or {})
                if parsed:
                    out.append(parsed)
            total = int((j or {}).get("totalResults", 0) or 0)
            start += 2000
            if start >= total or not vulns:
                break
            await asyncio.sleep(delay)
        await asyncio.sleep(delay * 0.5)
        return out

    async def nvd_by_keyword(self, keyword: str):
        out = []
        start = 0
        for _ in range(2):
            j = await self.http.get_json(
                NVD_API,
                params={"keywordSearch": keyword, "keywordExactMatch": "",
                        "resultsPerPage": 2000, "startIndex": start},
                timeout=120)
            vulns = (j or {}).get("vulnerabilities") or []
            for v in vulns:
                parsed = parse_nvd(v.get("cve") or {})
                if parsed:
                    out.append(parsed)
            total = int((j or {}).get("totalResults", 0) or 0)
            if not vulns or (start + 2000) >= total:
                break
            start += 2000
            await asyncio.sleep(0.6 if self.cfg.nvd_key else 6.5)
        return out

    async def src_kev(self, kev_meta):
        j = await self.http.get_json(KEV_URL, timeout=60)
        out = []
        for e in (j or {}).get("vulnerabilities", []):
            cid = str(e.get("cveID", "")).upper()
            if cid:
                kev_meta[cid] = {
                    "name": e.get("vulnerabilityName"),
                    "dateAdded": e.get("dateAdded"),
                    "ransomware": e.get("knownRansomwareCampaignUse"),
                }
                out.append({"id": cid, "description": e.get("shortDescription", "")})
        return out

    async def src_epss(self, cve_ids):
        out = {}
        ids = sorted(set(cve_ids))
        for i in range(0, len(ids), 100):
            chunk = ids[i:i + 100]
            j = await self.http.get_json(
                EPSS_API, params={"cve": ",".join(chunk), "limit": 100}, timeout=30)
            for d in (j or {}).get("data", []):
                out[d["cve"].upper()] = {"score": float(d["epss"]),
                                         "percentile": float(d["percentile"])}
            await asyncio.sleep(0.4)
        return out

    async def src_circl(self, vendor, product):
        j = await self.http.get_json(
            f"{CIRCL_API}/search/{quote(vendor)}/{quote(product)}", timeout=60)
        if isinstance(j, dict):
            j = j.get("results", [])
        out = []
        for it in (j or [])[:300]:
            cid = str(it.get("id") or "").upper()
            cvss = next((it[k] for k in ("cvss", "cvss3") if isinstance(it.get(k), (int, float))), None)
            desc = it.get("summary") or it.get("description") or ""
            if cid.startswith("CVE-"):
                out.append({"id": cid, "cvss": cvss, "description": desc[:500]})
        return out

    async def src_osv(self, package, ecosystem):
        body = {"package": {"name": package, "ecosystem": ecosystem}}
        response = await self.http.post(OSV_API, json_body=body, timeout=45)
        # HttpClient.post returns HttpResponse, unlike get_json.  Parse its
        # body here rather than treating the response object as a mapping.
        try:
            j = json.loads(response.body)
        except (AttributeError, TypeError, json.JSONDecodeError):
            j = {}
        out = []
        for v in (j or {}).get("vulns", [])[:200]:
            parsed = parse_osv_item(v)
            if parsed:
                out.append(parsed)
        return out

    async def src_ghsa(self, ecosystem):
        headers = {"Authorization": f"Bearer {self.cfg.gh_token}",
                   "Accept": "application/vnd.github+json"}
        out = []
        for page in range(1, 4):
            params = {"per_page": 100, "page": page, "ecosystem": ecosystem}
            data = await self.http.get_json(GHSA_API, params=params, headers=headers,
                                            timeout=30)
            if not isinstance(data, list):
                break
            for adv in data:
                cid = adv.get("cve_id")
                cvss = ((adv.get("cvss") or {}).get("score"))
                if cid and cvss:
                    out.append({"id": cid.upper(), "cvss": float(cvss),
                                "description": (adv.get("summary") or "")[:400]})
            if len(data) < 100:
                break
            await asyncio.sleep(0.5)
        return out

    async def src_exploitdb(self, edb_map):
        r = await self.http.get(EXPLOITDB_CSV, timeout=120)
        count = 0
        for line in r.body.splitlines()[1:]:
            parts = line.split(",", 16)
            if len(parts) < 12:
                continue
            edb_id = parts[0].strip()
            codes = parts[11].strip().strip('"')
            for cve in CVE_RE.findall(codes):
                lst = edb_map.setdefault(cve.upper(), [])
                if edb_id not in lst:
                    lst.append(edb_id)
                count += 1
        return []

    def correlate(self, cves, hits):
        """Annotate each CVE with matched hosts + correlation basis.

        basis: cpe+version (verified) > cpe > keyword.
        """
        host_map: dict[str, set] = {}
        rank = {"cpe+version": 2, "cpe": 1, "keyword": 0}
        for c in cves.values():
            cpes = [x.lower() for x in c.get("cpes", []) or []]
            desc_l = (c.get("description") or "").lower()
            affected = c.get("affected") or []
            matched_hosts: set[str] = set()
            best_basis = ""
            for h in hits:
                vp = f":{h['vendor']}:"
                pp = f":{h['product']}:"
                cpe_match = any(vp in x and pp in x for x in cpes)
                kw_match = not cpe_match and h["product"].lower() in desc_l
                if not (cpe_match or kw_match):
                    continue
                basis = "cpe" if cpe_match else "keyword"
                if h.get("version"):
                    ranges = [a for a in affected if pp in a["cpe"].lower()]
                    if ranges:
                        in_range = any(
                            version_satisfies(h["version"], a) is True
                            for a in ranges)
                        exact = any(
                            len(x.split(":")) > 5 and x.split(":")[5] == h["version"]
                            for x in cpes)
                        if not (in_range or exact):
                            continue
                        basis = "cpe+version"
                matched_hosts.update(h["hosts"])
                if rank[basis] > rank.get(best_basis, -1):
                    best_basis = basis
            if matched_hosts:
                c["matched_hosts"] = sorted(matched_hosts)
                c["correlation_basis"] = best_basis
                for h in matched_hosts:
                    host_map.setdefault(h, set()).add(c["id"].upper())
        return host_map

    def emit_findings(self, ordered_cves) -> None:
        """Only correlated CVEs become findings; KEV/EPSS are enrichment."""
        status_by_basis = {
            "cpe+version": ("finding", "high"),
            "cpe": ("candidate", "medium"),
            "keyword": ("candidate", "low"),
        }
        correlated = [c for c in ordered_cves if c.get("matched_hosts")]
        for c in correlated[:100]:
            score = c.get("cvss") or 0
            if score >= 9:
                sev = "critical"
            elif score >= 7:
                sev = "high"
            elif c["kev"]:
                sev = "critical"
            else:
                sev = "medium"
            basis = c.get("correlation_basis", "keyword")
            status, confidence = status_by_basis.get(basis,
                                                     ("candidate", "low"))
            ev = {
                "cve": c["id"],
                "cvss": c.get("cvss"),
                "basis": basis,
                "hosts": c["matched_hosts"][:4],
                "sources": c.get("sources", []),
                "kev": bool(c["kev"]),
            }
            if c.get("epss_score") is not None:
                ev["epss"] = round(c["epss_score"], 3)
            if c.get("exploitdb_ids"):
                ev["exploitdb"] = c["exploitdb_ids"][:5]
            remediation = self.REMEDIATION_CVE + (
                " Item listado no CISA KEV (exploração ativa)."
                if c["kev"] else "")
            self.result.add("vulnerable_cve", sev,
                            ", ".join(c["matched_hosts"][:2]),
                            evidence=ev, source=",".join(c["sources"]),
                            status=status, confidence=confidence,
                            remediation=remediation)

    REMEDIATION_CVE = ("Atualize o componente para uma versão corrigida "
                       "e confirme a exposição do serviço.")


def parse_osv_item(v: dict) -> dict | None:
    """Pure OSV advisory -> normalized CVE dict (testable without network)."""
    cid = next((str(a).upper() for a in v.get("aliases", [])
                if str(a).upper().startswith("CVE-")), "")
    if not cid and str(v.get("id", "")).upper().startswith("CVE-"):
        cid = v["id"].upper()
    if not cid:
        return None
    score = None
    for s in v.get("severity", []):
        nums = re.findall(r"\b(\d{1,2}\.\d)\b", s.get("score", "") or "")
        if nums:
            score = float(nums[-1])
            break
    return {"id": cid, "cvss": score,
            "description": (v.get("summary") or v.get("details") or "")[:500]}


def parse_nvd(cve: dict) -> dict | None:
    if not cve.get("id"):
        return None
    desc = ""
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            desc = d.get("value", "")
            break
    cvss = None
    vector = None
    for mk in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        arr = cve.get("metrics", {}).get(mk)
        if arr:
            cd = arr[0].get("cvssData") or {}
            if cd.get("baseScore") is not None:
                cvss = float(cd["baseScore"])
                vector = cd.get("vectorString")
                break
    cwes = []
    for w in cve.get("weaknesses", []):
        for dd in w.get("description", []):
            v = dd.get("value", "")
            if v.startswith("CWE-") and v not in cwes:
                cwes.append(v)
    cpes = []
    affected = []
    for cfg in cve.get("configurations", []):
        for node in cfg.get("nodes", []):
            for cm in node.get("cpeMatch", []):
                cr = cm.get("criteria")
                if not cr:
                    continue
                cpes.append(cr)
                if any(cm.get(k) for k in ("versionStartIncluding",
                                           "versionStartExcluding",
                                           "versionEndIncluding",
                                           "versionEndExcluding")):
                    affected.append({
                        "cpe": cr,
                        "start_inc": cm.get("versionStartIncluding"),
                        "start_exc": cm.get("versionStartExcluding"),
                        "end_inc": cm.get("versionEndIncluding"),
                        "end_exc": cm.get("versionEndExcluding"),
                    })
    refs = [r.get("url", "") for r in (cve.get("references") or [])][:20]
    return {"id": cve["id"].upper(), "description": desc[:800], "cvss": cvss,
            "vector": vector, "cwes": cwes, "cpes": cpes[:40],
            "affected": affected[:20], "references": refs,
            "published": cve.get("published"), "status": cve.get("vulnStatus")}


def _ver_tuple(v) -> tuple | None:
    nums = re.findall(r"\d+", str(v))
    return tuple(int(x) for x in nums[:4]) if nums else None


def version_satisfies(version: str, aff: dict) -> bool | None:
    """True/False when a declared range exists; None when no range info."""
    v = _ver_tuple(version)
    has_range = False
    for key, ok in (
        ("start_inc", lambda a, b: a >= b),
        ("start_exc", lambda a, b: a > b),
        ("end_inc", lambda a, b: a <= b),
        ("end_exc", lambda a, b: a < b),
    ):
        raw = aff.get(key)
        if not raw:
            continue
        r = _ver_tuple(raw)
        if v is None or r is None:
            return True
        if not ok(v, r):
            return False
        has_range = True
    return True if has_range else None
