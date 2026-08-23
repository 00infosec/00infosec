from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

from . import BRAND, __version__
from .core.ui import UI
from .modules import MODULES

PROFILES = {
    "quick": {"recon", "leakhunt"},
    "default": set(MODULES.keys()),
    "deep": set(MODULES.keys()),
    "passive": {"recon", "leakhunt", "phishlab"},
}

MODULE_ORDER = ("recon", "cvescan", "jsleak", "leakhunt", "cloudhunt",
                "phishlab")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="infosec",
        description=f"{BRAND} v{__version__} - unified recon framework",
    )
    p.add_argument("domain", nargs="*", help="dominio(s) alvo")
    p.add_argument("--config", metavar="ARQUIVO_JSON",
                   help="carrega defaults operacionais de um arquivo JSON")
    p.add_argument("-p", "--profile", choices=list(PROFILES), default="default")
    p.add_argument("--only", help="modulos separados por virgula")
    p.add_argument("--skip", help="modulos a pular")
    p.add_argument("-o", "--out", default="infosec_out")
    p.add_argument("--proxy", help="HTTP/SOCKS proxy (socks requer aiohttp-socks)")
    p.add_argument("--deep", action="store_true",
                   help="recon: brute + permute + takeover + internetdb completo")
    p.add_argument("--passive", action="store_true",
                   help="nenhuma conexao direta ao alvo (sem probe/stack/internetdb)")
    p.add_argument("--stack", action="store_true",
                   help="recon: fingerprint de tecnologias (ja incluido no default)")
    p.add_argument("--max-permutations", type=int, default=250)
    p.add_argument("--max-candidates", type=int, default=400)
    p.add_argument("--max-probe-hosts", type=int, default=400,
                   help="teto de hosts probeados pelo recon (default 400)")
    p.add_argument("--resume", action="store_true",
                   help="reaproveita checkpoint.json do diretorio de saida")
    p.add_argument("--baseline", metavar="SCAN_JSON",
                   help="compara com scan.json anterior (NOVO/RESOLVIDO/ALTERADO)")
    p.add_argument("--allow-private", action="store_true",
                   help="permite alvos em IPs privados/loopback (default: bloqueado)")
    p.add_argument("--exclude-host", default="",
                   help="hosts excluidos do escopo, separados por virgula")
    p.add_argument("--include-sensitive", action="store_true",
                   help="nao mascara segredos/senhas nos outputs locais "
                        "(MCP sempre mascara)")
    p.add_argument("--max-requests", type=int, default=0,
                   help="teto global de requisicoes HTTP (0 = ilimitado)")
    p.add_argument("--max-duration", default="0",
                   help="tempo maximo do scan ex: 20m, 90s, 2h (0 = sem limite)")
    p.add_argument("--concurrency", type=int, default=30)
    p.add_argument("--rate-limit", type=float, default=0,
                   help="requisicoes por segundo globais (0 = sem limite)")
    p.add_argument("--fail-on", choices=("none", "low", "medium", "high", "critical"),
                   default="none", help="exit 3 se houver finding nessa severidade ou maior")
    p.add_argument("--nvd-key", default=None)
    p.add_argument("--gh-token", default=None)
    p.add_argument("--no-banner", action="store_true")
    p.add_argument("--list-modules", action="store_true")
    return p


def parse_args_with_config(parser: argparse.ArgumentParser, argv=None):
    raw = list(sys.argv[1:] if argv is None else argv)
    pre = argparse.ArgumentParser(add_help=False)
    pre.add_argument("--config")
    config_path = pre.parse_known_args(raw)[0].config
    if config_path:
        try:
            config = json.loads(Path(config_path).read_text(encoding="utf-8"))
        except Exception as e:
            raise ValueError(f"config ilegivel ({config_path}): {e}") from e
        if not isinstance(config, dict):
            raise ValueError("config deve ser um objeto JSON")
        allowed = {a.dest for a in parser._actions} - {"help", "domain", "config"}
        normalized = {str(k).replace("-", "_"): v for k, v in config.items()}
        unknown = sorted(set(normalized) - allowed)
        if unknown:
            raise ValueError(f"opcao desconhecida na config: {', '.join(unknown)}")
        injected = []
        for key, value in normalized.items():
            if value in (None, False, ""):
                continue
            flag = "--" + key.replace("_", "-")
            injected.append(flag)
            if value is not True:
                injected.append(str(value))
        raw = injected + raw
    return parser.parse_args(raw)


def fail_threshold_reached(ctx, threshold: str) -> bool:
    if threshold == "none":
        return False
    rank = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    minimum = rank[threshold]
    return any(f.status == "finding" and rank.get(f.severity, 0) >= minimum
               for f in ctx.findings)


def parse_duration(v) -> int:
    s = str(v or "0").strip().lower()
    if not s or s == "0":
        return 0
    mult = {"s": 1, "m": 60, "h": 3600}
    try:
        if s[-1] in mult:
            return int(float(s[:-1]) * mult[s[-1]])
        return int(float(s))
    except ValueError:
        raise ValueError(f"duracao invalida: {v!r} (use ex: 20m, 90s, 2h)")


def resolve_modules(args) -> dict:
    names = set(PROFILES[getattr(args, "profile", "default")])
    only = getattr(args, "only", None)
    skip = getattr(args, "skip", None)
    if only:
        requested = [x.strip() for x in only.split(",") if x.strip()]
        unknown = [x for x in requested if x not in MODULES]
        if unknown:
            raise ValueError(f"modulo desconhecido: {', '.join(unknown)} "
                             f"(validos: {', '.join(MODULES)})")
        names = set(requested)
    if skip:
        names -= {n.strip() for n in skip.split(",")}
    ordered = {}
    for name in MODULE_ORDER:
        if name not in names:
            continue
        mod = MODULES[name]
        for dep in getattr(mod, "requires", ()):
            producer = next((m for m in MODULES.values()
                             if dep in m.provides and m is not mod), None)
            if producer and producer.name not in ordered:
                ordered[producer.name] = producer
        ordered[name] = mod
    return ordered


async def scan_domain(domain: str, args, ui: UI):
    from .runner import execute_scan
    ctx, results = await execute_scan(domain, args, ui=ui)
    print_summary_panel(ui, ctx, results)
    return ctx


def print_summary_panel(ui: UI, ctx, results):
    c = ui.console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text

    tbl = Table.grid(padding=(0, 3))
    tbl.add_column(style="muted", justify="right")
    tbl.add_column(style="label")
    totals = ctx.findings_by_severity()
    st_tot: dict[str, int] = {}
    for f in ctx.findings:
        st_tot[f.status] = st_tot.get(f.status, 0) + 1
    tbl.add_row("[primary]TARGET[/primary]", f"[host]{ctx.domain}[/host]")
    tbl.add_row("elapsed", f"[accent]{ctx.elapsed:.0f}s[/accent]")
    tbl.add_row("", "")
    for st in ("finding", "candidate", "observation"):
        n = st_tot.get(st, 0)
        style = {"finding": "err", "candidate": "warn",
                 "observation": "accent"}[st]
        tbl.add_row(st, f"[{style}]{n}[/{style}]")
    for sev in ("critical", "high", "medium", "low"):
        style = {"critical": "err", "high": "warn", "medium": "label",
                 "low": "accent"}[sev]
        n = totals.get(sev, 0)
        tbl.add_row(f"  {sev}", f"[{style}]{n}[/{style}]")

    data = ctx.data
    subs = len(data.get("subdomains") or ())
    alive = len(data.get("hosts_alive") or ())
    cves = len(data.get("cves") or ())
    buckets_open = sum(1 for b in (data.get("buckets") or []) if b.get("open"))
    creds = len(data.get("creds") or ())
    secrets = len(data.get("secrets") or [])
    typos_high = sum(1 for t in (data.get("typosquats") or [])
                     if t.get("score", 0) >= 40)
    extra = [
        ("subdomains", subs), ("alive hosts", alive), ("CVEs (total)", cves),
        ("JS secrets", secrets), ("creds vazadas", creds),
        ("buckets OPEN", buckets_open), ("phish high-score", typos_high),
    ]
    blocked = list(getattr(ctx.scope, "blocked", []) or []) if ctx.scope else []
    if blocked:
        extra.append(("bloqueadas pelo escopo", len(blocked)))
    for k, v in extra:
        tbl.add_row(k, f"[count]{v}[/count]" if v else "[muted]0[/muted]")
    errs = [f"{n}: {r.error}" for n, r in results.items() if r.status == "err"]
    c.print()
    c.print(Panel(tbl, title="[primary]/ SCAN COMPLETE /[/primary]",
                  border_style="primary"))
    if errs:
        wtxt = "\n".join(f"  [err]![/err] {e_}" for e_ in errs)
        c.print(Panel(Text.from_markup(wtxt), title="[err]/ erros /[/err]",
                      border_style="err"))
    c.print(f"\n  [ok]report:[/ok]   [host]{ctx.out_dir / 'report.html'}[/host]")
    c.print(f"  [ok]markdown:[/ok] [host]{ctx.out_dir / 'report.md'}[/host]")
    c.print(f"  [ok]json:[/ok]     [host]{ctx.out_dir / 'scan.json'}[/host]")
    c.print(f"  [ok]sarif:[/ok]    [host]{ctx.out_dir / 'findings.sarif'}[/host]")
    c.print(f"  [ok]jsonl:[/ok]    [host]{ctx.out_dir / 'findings.jsonl'}[/host]")
    c.print(f"  [ok]assets:[/ok]   [host]{ctx.out_dir / 'assets.jsonl'}[/host]\n")


def main(argv=None):
    parser = build_parser()
    try:
        args = parse_args_with_config(parser, argv)
    except ValueError as e:
        parser.error(str(e))

    if args.list_modules:
        for name, mod in MODULES.items():
            deps = ",".join(mod.requires) or "-"
            print(f"{name:12s} provides={','.join(mod.provides):40s} requires={deps}")
        return 0

    if not args.domain:
        parser.error("informe ao menos um dominio (ou --list-modules)")

    if args.profile == "deep":
        args.deep = True
    if args.passive:
        args.profile = "passive"
    try:
        args.max_duration = parse_duration(args.max_duration)
    except ValueError as e:
        parser.error(str(e))

    try:
        modules = resolve_modules(args)
    except ValueError as e:
        ui_err = UI(no_banner=True, stderr=True)
        ui_err.console.print(f"[err]{e}[/err]")
        return 2

    from .core.scope import validate_domain
    domains = []
    for raw in args.domain:
        try:
            domains.append(validate_domain(raw))
        except ValueError as e:
            ui_err = UI(no_banner=True, stderr=True)
            ui_err.console.print(f"[err]{e}[/err]")
            return 2

    ui = UI(no_banner=args.no_banner)
    ui.console.print(ui.status_panel([
        ("target", ", ".join(domains)),
        ("profile", args.profile),
        ("modules", ", ".join(modules)),
        ("proxy", args.proxy or "-"),
        ("scope", "privados permitidos" if args.allow_private
         else "IPs privados bloqueados"),
        ("masking", "OFF (--include-sensitive)" if args.include_sensitive
         else "ON"),
        ("output", str(Path(args.out).resolve())),
    ]))
    ui.console.print()

    exit_code = 0
    for d in domains:
        try:
            ctx = asyncio.run(scan_domain(d, args, ui))
            if fail_threshold_reached(ctx, args.fail_on):
                exit_code = 3
        except KeyboardInterrupt:
            ui.console.print("\n[warn]interrompido — checkpoint salvo, "
                             "continue com --resume[/warn]")
            return 130
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
