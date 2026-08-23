"""DNS fan-out regression tests."""
from __future__ import annotations

import asyncio

from infosec_recon.core.dnsx import DnsPool


def test_resolve_many_keeps_task_count_bounded():
    class FakePool(DnsPool):
        def __init__(self):
            self.peak_tasks = 0

        async def resolve(self, host: str, *, timeout: float = 8) -> dict:
            self.peak_tasks = max(self.peak_tasks, len(asyncio.all_tasks()))
            await asyncio.sleep(0)
            return {"host": host, "A": [], "AAAA": [], "CNAME": [],
                    "alive": False}

    async def run():
        pool = FakePool()
        hosts = [f"host-{i}.example.com" for i in range(2554)]
        progress = []
        records = await pool.resolve_many(
            hosts, concurrency=20,
            on_progress=lambda done, total: progress.append((done, total)))
        return pool, records, progress

    pool, records, progress = asyncio.run(run())
    assert len(records) == 2554
    assert pool.peak_tasks <= 21
    assert progress[-1] == (2554, 2554)


def test_resolve_queries_record_types_in_parallel():
    class Record:
        def __init__(self, value):
            self.value = value

        def to_text(self):
            return self.value

    class Resolver:
        def __init__(self):
            self.active = 0
            self.peak = 0

        async def resolve(self, host, rtype):
            self.active += 1
            self.peak = max(self.peak, self.active)
            await asyncio.sleep(0)
            self.active -= 1
            return [Record("192.0.2.1" if rtype == "A" else "target.example.com.")]

    async def run():
        pool = DnsPool(concurrency=1)
        pool._resolver = Resolver()
        record = await pool.resolve("www.example.com")
        return pool, record

    pool, record = asyncio.run(run())
    assert pool._resolver.peak == 3
    assert record["alive"] is True


def test_resolve_many_empty_input():
    async def run():
        return await DnsPool().resolve_many([])

    assert asyncio.run(run()) == []
