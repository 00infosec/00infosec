from __future__ import annotations

import asyncio
from typing import Callable

try:
    import dns.asyncresolver
    import dns.exception
    HAS_DNS = True
except ImportError:
    HAS_DNS = False

PUBLIC_RESOLVERS = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]


class DnsPool:
    def __init__(self, *, concurrency: int = 40):
        self.sem = asyncio.Semaphore(concurrency)
        self._resolver = None
        if HAS_DNS:
            r = dns.asyncresolver.Resolver()
            r.nameservers = PUBLIC_RESOLVERS
            r.timeout = 2
            r.lifetime = 4
            self._resolver = r

    @property
    def available(self) -> bool:
        return self._resolver is not None

    async def resolve(self, host: str, *, timeout: float = 8) -> dict:
        rec = {"host": host, "A": [], "AAAA": [], "CNAME": [], "alive": False}
        if self._resolver is None:
            return await self._resolve_os(host, rec, timeout)
        async with self.sem:
            async def query(rtype: str) -> tuple[str, list[str]]:
                try:
                    ans = await asyncio.wait_for(
                        self._resolver.resolve(host, rtype), timeout=timeout
                    )
                    return rtype, sorted({r.to_text().strip(".") for r in ans})
                except Exception:
                    return rtype, []

            for rtype, values in await asyncio.gather(
                    *(query(rtype) for rtype in ("A", "AAAA", "CNAME"))):
                rec[rtype] = values
        rec["alive"] = bool(rec["A"] or rec["AAAA"] or rec["CNAME"])
        return rec

    async def _resolve_os(self, host: str, rec: dict, timeout: float) -> dict:
        loop = asyncio.get_running_loop()
        try:
            infos = await asyncio.wait_for(
                loop.getaddrinfo(host, None, proto=0), timeout=timeout
            )
            for info in infos:
                ip = info[4][0]
                if ":" in ip and ip not in rec["AAAA"]:
                    rec["AAAA"].append(ip)
                elif ":" not in ip and ip not in rec["A"]:
                    rec["A"].append(ip)
        except Exception:
            pass
        rec["alive"] = bool(rec["A"] or rec["AAAA"])
        return rec

    async def resolve_many(
            self, hosts, *, concurrency: int = 40,
            on_progress: Callable[[int, int], None] | None = None) -> list[dict]:
        queue: asyncio.Queue[str] = asyncio.Queue()
        for host in hosts:
            queue.put_nowait(host)
        if queue.empty():
            return []

        out: list[dict] = []
        total = queue.qsize()
        completed = 0

        async def worker() -> None:
            nonlocal completed
            while True:
                try:
                    host = queue.get_nowait()
                except asyncio.QueueEmpty:
                    return
                try:
                    out.append(await self.resolve(host))
                finally:
                    queue.task_done()
                completed += 1
                if on_progress:
                    try:
                        on_progress(completed, total)
                    except Exception:
                        pass

        worker_count = min(max(1, concurrency), queue.qsize())
        tasks = [asyncio.create_task(worker()) for _ in range(worker_count)]
        try:
            await asyncio.gather(*tasks)
        except BaseException:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            raise
        return out

    async def detect_wildcard(self, domain: str, samples: int = 3) -> dict:
        wc_ips: set = set()
        wc_cnames: set = set()
        if self._resolver is None:
            return {"ips": [], "cnames": [], "is_wildcard": False}
        import random
        import string
        for _ in range(samples):
            label = "".join(random.choices(string.ascii_lowercase + string.digits, k=14))
            rec = await self.resolve(f"{label}.{domain}", timeout=5)
            wc_ips.update(rec["A"] + rec["AAAA"])
            wc_cnames.update(c.lower() for c in rec["CNAME"])
        return {"ips": wc_ips, "cnames": wc_cnames,
                "is_wildcard": bool(wc_ips or wc_cnames)}

    @staticmethod
    def is_wildcard_hit(rec: dict, wc: dict) -> bool:
        ips = set(rec.get("A", [])) | set(rec.get("AAAA", []))
        cns = {c.lower() for c in rec.get("CNAME", [])}
        wc_ips = set(wc.get("ips") or [])
        wc_cns = set(wc.get("cnames") or [])
        if wc_ips and ips and ips <= wc_ips:
            return True
        if wc_cns and cns and cns <= wc_cns and not (ips - wc_ips):
            return True
        return False

    async def ptr(self, ip: str, *, lifetime: float = 3) -> list[str]:
        if self._resolver is None:
            return []
        try:
            ans = await self._resolver.resolve_address(ip, lifetime=lifetime)
            return [r.to_text().strip(".").lower() for r in ans]
        except Exception:
            return []
