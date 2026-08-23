"""MCP server exposing 00INFOSEC RECON to MCP clients.

Works with the official `mcp` SDK 1.x (FastMCP) and 2.x (MCPServer).
Run with: python -m infosec_recon.mcp_server
"""
from __future__ import annotations

import asyncio
import json
import sys
import time
import uuid
from argparse import Namespace
from pathlib import Path

try:
    from mcp.server.fastmcp import FastMCP as _Server
    _SDK = "1.x"
except ImportError:
    try:
        from mcp.server.mcpserver import MCPServer as _Server
        _SDK = "2.x"
    except ImportError as e:
        print("mcp package missing. pip install 'infosec-recon[mcp]' "
              "or pip install mcp", file=sys.stderr)
        raise SystemExit(1) from e

from . import BRAND, __version__
from .cli import build_parser, resolve_modules
from .core.net import sanitize_slug
from .core.redact import mask_record
from .core.ui import UI
from .runner import execute_scan

server = _Server(
    BRAND,
    title=BRAND,
    description="Unified OSINT/attack-surface recon framework",
    instructions=(
        "Run authorized security-recon scans and query findings. "
        "Start with run_scan (returns scan_id), poll scan_status, then "
        "get_findings / get_scan_data. Only scan targets you are "
        "authorized to test. Scan records survive server restarts "
        "(list_scans)."
    ),
    version=__version__,
)

SCANS: dict[str, dict] = {}
MAX_IN_MEMORY = 20


def _scans_dir(out_dir: str) -> Path:
    root = Path(out_dir).resolve()
    d = root / ".scans"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _persist_scan(scan_id: str, entry: dict):
    try:
        path = _scans_dir(entry.get("store_root", "infosec_out")) / \
            f"{scan_id}.json"
        # Context may retain raw collected data; MCP persistence never does.
        doc = {k: v for k, v in entry.items() if k not in ("task", "ctx")}
        doc = mask_record(doc, include_sensitive=False)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(doc, ensure_ascii=False, default=str),
                       encoding="utf-8")
        tmp.replace(path)
    except Exception as e:
        print(f"[infosec-mcp] persist failed: {e}", file=sys.stderr)


def _load_scan(path: Path) -> dict | None:
    try:
        entry = json.loads(path.read_text(encoding="utf-8"))
        entry.pop("task", None)
        entry.pop("ctx", None)
        entry["store_root"] = entry.get("store_root") or str(path.parent.parent)
        entry["hydrated"] = True
        return entry
    except Exception:
        return None


def _restore_scan(scan_id: str, out_dir: str | None = None) -> dict | None:
    roots = []
    known = SCANS.get(scan_id)
    if known and known.get("store_root"):
        roots.append(known["store_root"])
    if out_dir:
        roots.append(out_dir)
    roots.append("infosec_out")
    for root in dict.fromkeys(str(Path(r).resolve()) for r in roots):
        p = Path(root) / ".scans" / f"{scan_id}.json"
        if not p.exists():
            continue
        entry = _load_scan(p)
        if entry:
            SCANS[scan_id] = entry
            _evict()
            return entry
    return None


def _evict():
    """Keep only the most recent MAX_IN_MEMORY entries fully loaded."""
    finished = [(sid, e) for sid, e in SCANS.items()
                if e.get("status") in ("done", "error", "cancelled")]
    if len(SCANS) <= MAX_IN_MEMORY or len(finished) < 2:
        return
    finished.sort(key=lambda x: x[1].get("finished") or 0)
    excess = len(SCANS) - MAX_IN_MEMORY
    for sid, _ in finished[:excess]:
        e = SCANS[sid]
        slim = {k: v for k, v in e.items() if k not in ("ctx", "results")}
        slim["hydrated"] = False
        SCANS[sid] = slim


def _get_entry(scan_id: str, out_dir: str | None = None) -> dict | None:
    entry = SCANS.get(scan_id)
    if entry is None or entry.get("hydrated") is False:
        entry = _restore_scan(scan_id, out_dir)
    return entry


def _args_ns(**kw) -> Namespace:
    defaults = build_parser().parse_args(["example.invalid"])
    for k in ("domain",):
        delattr(defaults, k)
    for k, v in kw.items():
        setattr(defaults, k, v)
    return defaults


async def _run_scan_task(scan_id: str, domain: str, args: Namespace):
    entry = SCANS[scan_id]
    try:
        ui = UI(no_banner=True, stderr=True)
        ctx, results = await execute_scan(domain, args, quiet_console=True,
                                          ui=ui)
        entry["ctx"] = ctx
        entry["results"] = {n: r.to_dict() for n, r in results.items()}
        entry["data_summary"] = _summarize_data(ctx.data)
        entry["status"] = "done"
        entry["finished"] = time.time()
    except Exception as e:
        entry["status"] = "error"
        entry["error"] = f"{type(e).__name__}: {e}"
        entry["finished"] = time.time()
    finally:
        _persist_scan(scan_id, entry)
        _evict()


def _summarize_data(d: dict) -> dict:
    summary = {
        "subdomains": sorted(d.get("subdomains") or ())[:500],
        "hosts_alive": sorted(d.get("hosts_alive") or ()),
        "stack": d.get("stack") or {},
        "cves_top": [
            {k: c.get(k) for k in ("id", "cvss", "severity", "kev",
                                   "matched_hosts", "description")}
            for c in (d.get("cves") or [])[:40]],
        "buckets_open": [b for b in (d.get("buckets") or []) if b.get("open")],
        "creds": (d.get("creds") or [])[:100],
        "emails_count": len(d.get("emails") or ()),
        "secrets": (d.get("secrets") or [])[:60],
        "typosquats_high": [t for t in (d.get("typosquats") or [])
                            if t.get("score", 0) >= 40][:60],
        "rdap": d.get("rdap"),
        "internetdb": d.get("internetdb"),
        "assets": (d.get("assets") or [])[:500],
    }
    return mask_record(summary, include_sensitive=False)


def _json(data: dict) -> str:
    """MCP has no sensitive-output opt-in; always redact its responses."""
    return json.dumps(mask_record(data, include_sensitive=False),
                      ensure_ascii=False, default=str)


@server.tool()
def list_modules() -> str:
    """List all available scan modules with what they provide/require."""
    from .modules import MODULES
    return _json({
        name: {
            "description": mod.description,
            "provides": list(mod.provides),
            "requires": list(mod.requires),
        } for name, mod in MODULES.items()
    })


@server.tool()
async def run_scan(domain: str, profile: str = "default", only: str = "",
                   skip: str = "", deep: bool = False, proxy: str = "",
                   out_dir: str = "infosec_out",
                   max_probe_hosts: int = 400,
                   resume: bool = False,
                   allow_private: bool = False) -> str:
    """Start an OSINT/attack-surface scan on a target domain (background).

    Args:
        domain: target like example.com.br
        profile: quick | default | deep | passive
        only: comma-separated module names to include (overrides profile)
        skip: comma-separated modules to exclude
        deep: brute + permute + takeover + full InternetDB on recon
        proxy: optional HTTP/SOCKS proxy url
        max_probe_hosts: cap of hosts HTTP-probed by recon
        resume: reuse checkpoint and run only missing modules
        allow_private: permit private/loopback IPs in scope (default False)

    Returns scan_id immediately; poll scan_status afterwards.
    Secrets are ALWAYS masked over MCP. Only scan authorized targets.
    """
    from .core.scope import validate_domain
    try:
        domain = validate_domain(domain)
    except ValueError as e:
        return _json({"error": str(e)})
    if profile not in ("quick", "default", "deep", "passive"):
        profile = "default"
    args = _args_ns(profile=profile,
                    only=only or None, skip=skip or None,
                    deep=deep or profile == "deep",
                    passive=profile == "passive",
                    proxy=proxy or None, out=out_dir,
                    max_permutations=250, max_candidates=400,
                    max_probe_hosts=max(10, int(max_probe_hosts)),
                    resume=bool(resume),
                    allow_private=bool(allow_private),
                    include_sensitive=False)
    modules = list(resolve_modules(args))
    scan_id = uuid.uuid4().hex[:10]
    entry = {
        "domain": domain, "status": "running", "started": time.time(),
        "task": asyncio.create_task(_run_scan_task(scan_id, domain, args)),
        "out_dir": str(Path(args.out).resolve() / sanitize_slug(domain)),
        "store_root": str(Path(args.out).resolve()),
        "modules": modules, "ctx": None, "results": None, "error": None,
    }
    SCANS[scan_id] = entry
    _persist_scan(scan_id, {k: v for k, v in entry.items() if k != "task"})
    _evict()
    return _json({"scan_id": scan_id, "domain": domain,
                       "modules": modules, "out_dir": entry["out_dir"],
                       "note": "poll scan_status(scan_id); "
                               "records survive restarts (list_scans)"})


@server.tool()
async def list_scans(out_dir: str = "infosec_out", limit: int = 30) -> str:
    """List persisted scans (survive server restarts), newest first."""
    d = Path(out_dir).resolve() / ".scans"
    rows = []
    if d.exists():
        for p in sorted(d.glob("*.json"), key=lambda x: x.stat().st_mtime,
                        reverse=True)[:max(1, min(limit, 100))]:
            try:
                e = json.loads(p.read_text(encoding="utf-8"))
                e["store_root"] = str(Path(out_dir).resolve())
                SCANS[p.stem] = e
                rows.append({"scan_id": p.stem, "domain": e.get("domain"),
                             "status": e.get("status"),
                             "started": e.get("started"),
                             "modules": e.get("modules")})
            except Exception:
                continue
    return _json({"count": len(rows), "scans": rows})


@server.tool()
async def scan_status(scan_id: str, out_dir: str = "infosec_out") -> str:
    """Progress/status of a running or finished scan."""
    e = _get_entry(scan_id, out_dir)
    if not e:
        return _json({"error": "unknown scan_id"})
    out = {"scan_id": scan_id, "domain": e["domain"], "status": e["status"],
           "elapsed_seconds": round((e.get("finished") or time.time())
                                    - e["started"], 1),
           "out_dir": e.get("out_dir")}
    if e.get("error"):
        out["error"] = e["error"]
    if e.get("results"):
        out["modules"] = {n: {"status": r["status"],
                              "elapsed": r["elapsed_seconds"],
                              "findings": len(r["findings"]),
                              "stats": r["stats"]}
                          for n, r in e["results"].items()}
    elif e.get("modules"):
        out["modules"] = {m: {"status": "?"} for m in e["modules"]}
    return _json(out)


@server.tool()
async def get_findings(scan_id: str, severity: str = "", module: str = "",
                       limit: int = 80, out_dir: str = "infosec_out") -> str:
    """Findings of a finished scan, optionally filtered by severity/module.

    Pass the same out_dir used by run_scan when recovering after a restart.
    """
    e = _get_entry(scan_id, out_dir)
    if not e or not e.get("results"):
        return _json({"error": "scan not finished or unknown"})
    rows = []
    for n, r in e["results"].items():
        if module and n != module:
            continue
        for f in r["findings"]:
            if severity and f.get("severity") != severity:
                continue
            rows.append(f)
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    rows.sort(key=lambda f: order.get(f.get("severity", "info"), 9))
    return _json({"total_matched": len(rows),
                  "findings": rows[:max(1, min(limit, 300))]})


@server.tool()
async def get_scan_data(scan_id: str, out_dir: str = "infosec_out") -> str:
    """Aggregated scan data; pass the original out_dir after a restart."""
    e = _get_entry(scan_id, out_dir)
    if not e:
        return _json({"error": "unknown scan_id"})
    summary = e.get("data_summary")
    if not summary and e.get("ctx"):
        summary = _summarize_data(e["ctx"].data)
    if not summary:
        return _json({"error": "scan not finished"})
    return _json(summary)


@server.tool()
async def cancel_scan(scan_id: str, out_dir: str = "infosec_out") -> str:
    """Cancel a running scan."""
    e = _get_entry(scan_id, out_dir)
    if not e:
        return _json({"error": "unknown scan_id"})
    task = e.get("task")
    if not task or e["status"] != "running":
        return _json({"status": e["status"], "note": "not running"})
    task.cancel()
    e["status"] = "cancelled"
    e["finished"] = time.time()
    _persist_scan(scan_id, {k: v for k, v in e.items() if k != "task"})
    return _json({"cancelled": True,
                       "note": "checkpoint kept; rerun with resume=true "
                               "to continue where it stopped"})


def main():
    server.run("stdio")


if __name__ == "__main__":
    main()
