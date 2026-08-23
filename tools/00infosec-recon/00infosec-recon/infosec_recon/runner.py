from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path

from .core.config import Config
from .core.dnsx import DnsPool
from .core.http import HttpClient
from .core.models import Finding, ModuleResult, ScanContext
from .core.net import sanitize_slug
from .core.redact import mask_record
from .core.scope import build_scope
from .core.ui import UI
from .engine.scheduler import run_pipeline
from .report.assets import build_asset_inventory
from .report.html import build_html, write_sarif, write_scan_json
from .report.markdown import write_markdown

CHECKPOINT_FILE = "checkpoint.json"


async def execute_scan(domain: str, args, *, quiet_console: bool = False,
                       ui=None) -> tuple[ScanContext, dict]:
    """Run one full domain scan and persist reports (CLI + MCP shared)."""
    if ui is None:
        ui = UI(no_banner=getattr(args, "no_banner", True),
                stderr=quiet_console)
    out_root = Path(args.out).resolve()
    ctx = ScanContext(domain, out_root / sanitize_slug(domain), args)
    ctx.out_dir.mkdir(parents=True, exist_ok=True)
    ctx.scope = build_scope(domain, args)

    modules = MODULES_ORDER(args, ui)
    initial = None
    ckpt_path = ctx.out_dir / CHECKPOINT_FILE
    if getattr(args, "resume", False):
        initial = load_checkpoint(ckpt_path, set(modules))
        if initial:
            ui.console.print(
                f"[ok]resume:[/ok] {len(initial)} modulo(s) reaproveitados")

    cfg = Config(args)

    def _checkpoint(result):
        save_checkpoint(ctx, modules, results_partial=ctx.results)

    duration = getattr(args, "max_duration", 0) or 0
    async with HttpClient(
        cfg,
        connector_limit=max(10, int(getattr(args, "concurrency", 30) or 30)),
        scope=ctx.scope,
        max_requests=getattr(args, "max_requests", None) or None,
        rate_rps=getattr(args, "rate_limit", None) or None,
    ) as http:
        dns = DnsPool()
        try:
            results = await asyncio.wait_for(
                run_pipeline(ctx, modules, http, dns, cfg, ui,
                             initial=initial, on_module_done=_checkpoint),
                timeout=duration or None)
        except asyncio.TimeoutError:
            ui.console.print(f"[warn]max-duration {duration}s atingido — "
                             f"finalizando com o coletado (checkpoint salvo)[/warn]")
            results = {n: r for n, r in ctx.results.items()}
            for r in results.values():
                if r.status in ("queued", "waiting", "running"):
                    r.finish("err", "timeout global do scan")
        ctx.data["http_metrics"] = {
            "requests": http.metrics.requests,
            "errors": http.metrics.errors,
            "timeouts": http.metrics.timeouts,
            "rate_limited": http.metrics.rate_limited,
            "blocked_by_scope": http.metrics.blocked,
            "retries": http.metrics.retries,
            "by_host": dict(http.metrics.by_host),
        }

    all_settled = all(r.status in ("done", "skipped")
                      for r in results.values())
    if all_settled and ckpt_path.exists():
        ckpt_path.unlink()

    ctx.data["assets"] = build_asset_inventory(ctx)

    prev_baseline = None
    bpath = getattr(args, "baseline", None)
    if bpath:
        try:
            prev_baseline = json.loads(Path(bpath).read_text(encoding="utf-8"))
        except Exception as e:
            raise ValueError(f"baseline ilegivel ({bpath}): {e}")

    write_scan_json(ctx, results)

    diff = None
    if prev_baseline is not None:
        from .report.baseline import diff_scans
        cur_doc = json.loads((ctx.out_dir / "scan.json")
                             .read_text(encoding="utf-8"))
        diff = diff_scans(cur_doc, prev_baseline)
        cur_doc["baseline_diff"] = {
            "compared_to": str(bpath),
            "new_count": diff["new_count"],
            "resolved_count": diff["resolved_count"],
            "changed_count": diff["changed_count"],
            "new": diff["new"][:200],
            "resolved": diff["resolved"][:200],
            "changed": diff["changed"][:200],
        }
        (ctx.out_dir / "scan.json").write_text(
            json.dumps(cur_doc, indent=2, ensure_ascii=False),
            encoding="utf-8")

    build_html(ctx, results, baseline_diff=diff)
    write_markdown(ctx, results, baseline_diff=diff)
    write_sarif(ctx)
    _write_artifacts(ctx)
    _write_jsonl(ctx, include_sensitive=bool(getattr(args,
                                                     "include_sensitive",
                                                     False)))
    _write_assets_jsonl(ctx, include_sensitive=bool(getattr(
        args, "include_sensitive", False)))
    return ctx, results


def MODULES_ORDER(args, ui):  # noqa: N802
    from .cli import resolve_modules
    return resolve_modules(args)


def _write_jsonl(ctx, *, include_sensitive: bool):
    path = ctx.out_dir / "findings.jsonl"
    with open(path, "w", encoding="utf-8") as fh:
        for f in ctx.findings:
            rec = f.to_dict()
            rec = mask_record(rec, include_sensitive)
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")


def _write_assets_jsonl(ctx, *, include_sensitive: bool):
    path = ctx.out_dir / "assets.jsonl"
    with open(path, "w", encoding="utf-8") as fh:
        for asset in ctx.data.get("assets") or []:
            rec = mask_record(asset, include_sensitive)
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")


def surface_snapshot(ctx, cap_subs: int = 3000) -> dict:
    from .report.html import _surface
    return _surface(ctx)


def print_summary_panel(ui: UI, ctx, results):  # compat re-export
    from .cli import print_summary_panel as p
    p(ui, ctx, results)


def _write_artifacts(ctx):
    d = ctx.data

    def txt(name: str, lines) -> int:
        data = "\n".join(sorted(str(x) for x in lines if x)) + ("\n" if lines else "")
        (ctx.out_dir / name).write_text(data, encoding="utf-8")
        return len(lines)

    counts = {
        "subdomains.txt": txt("subdomains.txt", d.get("subdomains") or ()),
        "alive.txt": txt("alive.txt", d.get("hosts_alive") or ()),
        "urls.txt": txt("urls.txt", d.get("urls") or ()),
    }
    http_lines = [
        f"{r['status']} {r['url']} | {r.get('title', '')}"
        for r in sorted(d.get("http_records") or [],
                        key=lambda x: x.get("host", ""))
    ]
    counts["http.txt"] = txt("http.txt", http_lines)
    return counts


def save_checkpoint(ctx, modules: dict, *, results_partial,
                    last: ModuleResult | None = None):
    """Persist per-module state so an interrupted scan can be resumed."""
    doc = {
        "domain": ctx.domain,
        "timestamp": time.time(),
        "modules": {
            name: r.to_dict()
            for name, r in results_partial.items()
            if name in modules
        },
    }
    tmp = ctx.out_dir / (CHECKPOINT_FILE + ".tmp")
    tmp.write_text(json.dumps(doc, ensure_ascii=False), encoding="utf-8")
    tmp.replace(ctx.out_dir / CHECKPOINT_FILE)


def load_checkpoint(path: Path, planned: set[str]) -> dict[str, ModuleResult]:
    if not path.exists():
        return {}
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    out: dict[str, ModuleResult] = {}
    for name, data in (doc.get("modules") or {}).items():
        if name not in planned or data.get("status") != "done":
            continue
        r = ModuleResult(name)
        elapsed = float(data.get("elapsed_seconds") or 0)
        r.started = time.time() - elapsed
        r.ended = time.time()
        r.status = "done"
        r.stats = data.get("stats") or {}
        base = ("module", "type", "status", "severity", "confidence", "asset",
                "evidence", "source", "remediation", "collected_at")
        for fd in data.get("findings") or []:
            extra = {k: v for k, v in fd.items() if k not in base}
            ev = fd.get("evidence")
            if isinstance(ev, dict):
                ev = {**ev, **extra}
            elif extra:
                ev = {"summary": str(ev), **extra} if ev else dict(extra)
            else:
                ev = ev if isinstance(ev, dict) else (
                    {"summary": str(ev)} if ev else {})
            r.findings.append(Finding(
                module=fd.get("module", name), type=fd.get("type", "?"),
                severity=fd.get("severity", "info"),
                asset=fd.get("asset", fd.get("target", "")),
                status=fd.get("status", "finding"),
                confidence=fd.get("confidence", "medium"),
                evidence=ev or {},
                source=fd.get("source", ""),
                remediation=fd.get("remediation", ""),
                collected_at=fd.get("collected_at", ""),
            ))
        out[name] = r
    return out


def print_final(ui, ctx, results):  # legacy alias
    print_summary_panel(ui, ctx, results)
