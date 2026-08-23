from __future__ import annotations

import asyncio
import re

from ..core.net import registrable_core
from .base import Module

PROVIDERS = {
    "aws-s3": {
        "url_tpl": "https://{name}.s3.amazonaws.com/",
        "alt": "https://s3.amazonaws.com/{name}/",
        "exists_codes": [200, 403], "open_codes": [200],
    },
    "azure-blob": {
        "url_tpl": "https://{name}.blob.core.windows.net/?comp=list",
        "exists_codes": [200, 400, 403], "open_codes": [200],
    },
    "gcp-storage": {
        "url_tpl": "https://storage.googleapis.com/{name}/",
        "exists_codes": [200, 403, 401], "open_codes": [200],
    },
    "do-spaces": {
        "url_tpl": "https://{name}.nyc3.digitaloceanspaces.com/",
        "regions": ["nyc3", "sfo3", "ams3", "sgp1"],
        "exists_codes": [200, 403], "open_codes": [200],
    },
    "wasabi": {"url_tpl": "https://{name}.s3.wasabisys.com/",
               "exists_codes": [200, 403], "open_codes": [200]},
    "linode": {"url_tpl": "https://{name}.us-east-1.linodeobjects.com/",
               "exists_codes": [200, 403], "open_codes": [200]},
}

LISTING_MARKERS = {
    "aws-s3": ("<ListBucketResult", "<Contents>"),
    "azure-blob": ("<EnumerationResults", "<Blob>"),
    "gcp-storage": ("<ListBucketResult", "<Contents>"),
    "do-spaces": ("<ListBucketResult", "<Contents>"),
    "wasabi": ("<ListBucketResult", "<Contents>"),
    "linode": ("<ListBucketResult", "<Contents>"),
}

SUFFIXES = [
    "prod", "production", "dev", "development", "staging", "stg", "test", "qa",
    "backup", "backups", "bkp", "dump", "archive", "logs", "data", "assets",
    "static", "media", "uploads", "files", "docs", "images", "img", "private",
    "public", "internal", "config", "cache", "tmp", "old", "web", "app", "api",
    "cdn", "storage", "billing", "invoices", "reports", "users", "customers",
]
PREFIXES = ["backup", "backups", "data", "files", "uploads", "media", "prod",
            "dev", "stage", "internal", "private", "old", "archive", "logs"]
SEPARATORS = ["", "-", ".", "_"]


def generate_permutations(domain: str, max_perms: int = 250) -> list:
    core = registrable_core(domain)
    names = {core, domain.replace(".", "-"), domain.replace(".", "")}
    for s in SUFFIXES:
        for sep in SEPARATORS:
            names.add(f"{core}{sep}{s}")
            names.add(f"{s}{sep}{core}")
    for p in PREFIXES:
        for sep in SEPARATORS:
            names.add(f"{p}{sep}{core}")
    valid = []
    for n in names:
        n = n.strip("-._")
        if 3 <= len(n) <= 63 and re.match(r"^[a-z0-9][a-z0-9\-._]*[a-z0-9]$", n):
            valid.append(n)
    return sorted(set(valid))[:max_perms]


class CloudHuntModule(Module):
    name = "cloudhunt"
    description = "cloud buckets: S3/Azure/GCP/DO/Wasabi/Linode permutations"
    provides = ("buckets",)
    requires = ()

    async def run(self):
        d = self.ctx.domain
        perms = generate_permutations(d, getattr(self.ctx.args, "max_permutations", 250))
        core = registrable_core(d)
        hits = []
        errors = {"count": 0}
        sem = asyncio.Semaphore(30)

        async def check(provider, name, prov):
            async with sem:
                urls = [prov["url_tpl"].format(name=name)]
                if "regions" in prov:
                    for region in prov["regions"][1:]:
                        urls.append(prov["url_tpl"].format(name=name).replace(
                            list(prov["regions"])[0], region))
                if prov.get("alt"):
                    urls.append(prov["alt"].format(name=name))
                for url in urls:
                    try:
                        r = await self.http.get(url, timeout=10, retries=0,
                                                max_body=2000)
                    except Exception:
                        errors["count"] += 1
                        continue
                    if r.status in prov["exists_codes"]:
                        markers = LISTING_MARKERS.get(provider, ())
                        is_open = (r.status == 200 and bool(r.body) and
                                   any(mk in r.body for mk in markers))
                        hits.append({
                            "provider": provider, "name": name, "url": url,
                            "status": r.status, "open": is_open,
                            "attributed": bool(core) and core in name.lower(),
                        })
                        if is_open:
                            self.add("cloud_bucket_open",
                                     "critical" if hits[-1]["attributed"] else "high",
                                     name, evidence={"url": url,
                                                     "attributed": hits[-1]["attributed"],
                                                     "provider": provider},
                                     source=provider,
                                     status="finding", confidence="high")
                        return

        tasks = []
        for provider in PROVIDERS:
            prov = PROVIDERS[provider]
            for name in perms:
                tasks.append(check(provider, name, prov))
        tested = len(tasks)
        await asyncio.gather(*tasks)

        open_b = [h for h in hits if h["open"]]
        attr_open = [h for h in open_b if h["attributed"]]
        self.ctx.data["buckets"] = hits
        self.result.stats.update({
            "permutations": len(perms), "tested": tested,
            "exists": len(hits), "open": len(open_b),
            "open_attributed": len(attr_open),
        })
