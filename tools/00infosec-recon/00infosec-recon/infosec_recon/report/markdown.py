from __future__ import annotations

from datetime import datetime, timezone

from .. import BRAND, __version__
from ..core.redact import mask_record


def write_markdown(ctx, results, baseline_diff=None) -> None:
    sensitive = bool(getattr(ctx.args, "include_sensitive", False))
    lines = [
        f"# {BRAND} — {ctx.domain}", "",
        f"- Versão: {__version__}",
        f"- Scan: `{ctx.id}`",
        f"- Coletado: {datetime.now(timezone.utc).isoformat()}",
        f"- Ativos correlacionados: {len(ctx.data.get('assets') or [])}", "",
        "## Módulos", "", "| Módulo | Status | Achados | Duração |",
        "|---|---:|---:|---:|",
    ]
    for name, result in results.items():
        lines.append(f"| {name} | {result.status} | {len(result.findings)} | "
                     f"{result.elapsed:.1f}s |")

    lines += ["", "## Ativos", "", "| Ativo | Tipo | IPs | Portas | Tecnologias | Achados |",
              "|---|---|---|---|---|---:|"]
    for asset in (ctx.data.get("assets") or [])[:500]:
        techs = ", ".join(
            f"{name}{(' ' + info['version']) if info.get('version') else ''}"
            for name, info in (asset.get("technologies") or {}).items())
        lines.append("| " + " | ".join((
            asset["asset"], asset["kind"], ", ".join(asset.get("ips") or []),
            ", ".join(str(p) for p in asset.get("ports") or []), techs,
            str(len(asset.get("findings") or [])),
        )) + " |")

    lines += ["", "## Achados", ""]
    findings = [mask_record(f.to_dict(), sensitive) for f in ctx.findings]
    findings.sort(key=lambda f: (-{"critical": 4, "high": 3, "medium": 2,
                                  "low": 1}.get(f["severity"], 0), f["asset"]))
    if not findings:
        lines.append("Nenhum achado.")
    for finding in findings:
        lines += [
            f"### {finding['severity'].upper()} · {finding['type']}", "",
            f"- Ativo: `{finding['asset']}`",
            f"- Estado: {finding['status']} · confiança {finding['confidence']}",
            f"- Fonte: {finding['source'] or '-'}",
            f"- Evidência: `{finding.get('evidence') or {}}`",
            f"- Recomendação: {finding['remediation'] or '-'}", "",
        ]

    if baseline_diff is not None:
        lines += ["## Baseline", "",
                  f"- Novos: {baseline_diff['new_count']}",
                  f"- Resolvidos: {baseline_diff['resolved_count']}",
                  f"- Alterados: {baseline_diff['changed_count']}", ""]

    (ctx.out_dir / "report.md").write_text("\n".join(lines) + "\n",
                                             encoding="utf-8")
