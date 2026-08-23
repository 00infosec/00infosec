from __future__ import annotations

import asyncio
import time

from ..core.models import ModuleResult


async def run_pipeline(ctx, modules: dict, http, dns, cfg, ui, *,
                       initial: dict[str, ModuleResult] | None = None,
                       on_module_done=None):
    """Execute the module DAG in-process.

    A module waits (asyncio events keyed on provided data) for the producers
    of every key listed in its `requires`. Independent modules run concurrently.

    initial        : name -> ModuleResult already completed by a previous run
                     (resume); they are skipped but feed reports and unlock deps
    on_module_done : callback(result) invoked after each module finishes,
                     used for live checkpointing
    """
    from ..core.ui import LiveUI

    results: dict[str, ModuleResult] = {n: ModuleResult(n) for n in modules}
    resumed: set[str] = set()
    for name, prev in (initial or {}).items():
        if name in modules and prev.status == "done":
            prev.started = prev.ended = time.time()
            results[name] = prev
            resumed.add(name)

    for name, r in results.items():
        ctx.results[name] = r
        if name in resumed:
            ctx.merge_findings(r)

    done_events: dict[str, asyncio.Event] = {}
    for name, mod in modules.items():
        for key in mod.provides:
            ev = asyncio.Event()
            if name in resumed:
                ev.set()
            done_events[key] = ev
    for key, ev in done_events.items():
        producer_done = any(
            results[n].status == "done" for n, m in modules.items() if key in m.provides)
        if producer_done:
            ev.set()

    async def runner(name: str):
        cls = modules[name]
        result = results[name]
        if name in resumed:
            for key in cls.provides:
                done_events.setdefault(key, asyncio.Event()).set()
            return
        inst = None
        try:
            wait_keys = [k for k in cls.requires if k in done_events]
            if wait_keys:
                result.status = "waiting"
                await asyncio.gather(*(done_events[k].wait() for k in wait_keys))
            result.status = "running"
            inst = cls(ctx, http, dns, cfg, ui.console)
            inst.result = result
            await inst.run()
            result.finish("done")
        except Exception as e:
            result.finish("err", f"{type(e).__name__}: {e}"[:200])
        finally:
            ctx.merge_findings(result)
            for key in cls.provides:
                done_events.setdefault(key, asyncio.Event()).set()
            if on_module_done:
                try:
                    on_module_done(result)
                except Exception:
                    pass

    live_ctx = LiveUI(ui, results, ctx)
    async with live_ctx:
        tasks = [asyncio.create_task(runner(n)) for n in modules
                 if n not in resumed]
        await asyncio.gather(*tasks)
        live_ctx.refresh()

    for r in results.values():
        r.ended = r.ended or time.time()
    return results
