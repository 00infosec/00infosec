from __future__ import annotations

import json
from datetime import datetime, timezone
from html import escape as e

from .. import BRAND, __version__
from ..core.redact import mask_record

SEV_COLORS = {"critical": "#ff0044", "high": "#ffaa00", "medium": "#ffe066",
              "low": "#00f0ff", "info": "#7d8590", "unknown": "#7d8590",
              "none": "#7d8590"}
STATUS_COLORS = {"finding": "#ff0044", "candidate": "#ffaa00",
                 "observation": "#00f0ff"}
CONF_COLORS = {"high": "#00ff88", "medium": "#ffe066", "low": "#7d8590"}


def severity_totals(ctx) -> dict:
    out: dict[str, int] = {}
    for f in ctx.findings:
        out[f.severity] = out.get(f.severity, 0) + 1
    return out


def _surface(ctx) -> dict:
    d = ctx.data
    stack = {}
    for host, techs in (d.get("stack") or {}).items():
        stack[host] = {t: info.get("version") for t, info in techs.items()}
    return {
        "subdomains": sorted(d.get("subdomains") or ())[:3000],
        "alive": sorted(d.get("hosts_alive") or ()),
        "stack": stack,
        "cves": [{"id": c["id"], "severity": c.get("severity")}
                 for c in (d.get("cves") or [])[:500]],
    }


def write_scan_json(ctx, results):
    sensitive = bool(getattr(ctx.args, "include_sensitive", False))
    scope_info = {}
    if ctx.scope is not None:
        scope_info = {"domain": ctx.scope.domain,
                      "allow_private_ips": ctx.scope.allow_private_ips,
                      "blocked_total": len(ctx.scope.blocked),
                      "blocked_sample": ctx.scope.blocked[:100]}
    http_info = ctx.data.get("http_metrics")
    doc = {
        "scan": {
            "framework": BRAND, "version": __version__,
            "target": ctx.domain,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "elapsed_seconds": round(ctx.elapsed, 2),
            "scan_id": ctx.id,
            "include_sensitive": sensitive,
        },
        "surface": _surface(ctx),
        "assets": mask_record(ctx.data.get("assets") or [], sensitive),
        "scope": scope_info,
        "http": http_info or {},
        "source_health": {
            name: {"status": result.status,
                   "error": result.error,
                   "sources": result.stats.get("sources", {})}
            for name, result in results.items()
        },
        "results": {},
        "totals": severity_totals(ctx),
    }
    for n, r in results.items():
        rd = r.to_dict()
        rd["findings"] = mask_record(rd["findings"], sensitive)
        doc["results"][n] = rd
    (ctx.out_dir / "scan.json").write_text(
        json.dumps(doc, indent=2, ensure_ascii=False), encoding="utf-8")
    return doc


def write_sarif(ctx):
    sensitive = bool(getattr(ctx.args, "include_sensitive", False))
    rules = {}
    results = []
    for f in ctx.findings:
        rid = f"{f.module}/{f.type}"
        if rid not in rules:
            rules[rid] = {
                "id": rid,
                "shortDescription": {"text": f.type.replace("_", " ")},
                "defaultConfiguration": {"level": sarif_level(f.severity)},
                "properties": {"security-severity": sarif_score(f.severity)},
            }
        ev = mask_record(dict(f.evidence), sensitive)
        msg = f"[{f.module}] {f.type} em {f.asset}"
        if ev.get("summary"):
            msg += f": {ev['summary']}"
        elif ev.get("path"):
            msg += f": {ev['path']}"
        results.append({
            "ruleId": rid,
            "level": sarif_level(f.severity),
            "message": {"text": msg},
            "properties": {"status": f.status, "confidence": f.confidence,
                           "severity": f.severity, "source": f.source},
        })
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": BRAND, "version": __version__, "informationUri": "",
                "rules": list(rules.values()),
            }},
            "results": results,
        }],
    }
    (ctx.out_dir / "findings.sarif").write_text(
        json.dumps(doc, ensure_ascii=False), encoding="utf-8")


def sarif_level(sev: str) -> str:
    return {"critical": "error", "high": "error", "medium": "warning"}.get(sev, "note")


def sarif_score(sev: str) -> str:
    return {"critical": "9.5", "high": "8.0", "medium": "5.5",
            "low": "3.0"}.get(sev, "1.0")


def build_html(ctx, results, baseline_diff=None) -> str:
    sensitive = bool(getattr(ctx.args, "include_sensitive", False))
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    totals = severity_totals(ctx)

    rows_data = []
    for f in ctx.findings:
        fd = mask_record(f.to_dict(), sensitive)
        rows_data.append(fd)
    order_rank = {"finding": 0, "candidate": 1, "observation": 2}
    rows_data.sort(key=lambda x: (
        -{"critical": 4, "high": 3, "medium": 2}.get(x["severity"], 1),
        order_rank.get(x["status"], 3)))

    findings_rows = ""
    for f in rows_data:
        c = SEV_COLORS.get(f["severity"], "#7d8590")
        sc = STATUS_COLORS.get(f["status"], "#7d8590")
        cc = CONF_COLORS.get(f["confidence"], "#7d8590")
        ev_parts = []
        for k, v in (f.get("evidence") or {}).items():
            if v is None:
                continue
            ev_parts.append(f"{k}: {v}")
        ev_txt = " · ".join(ev_parts)[:220]
        findings_rows += (
            f'<tr class="row" data-sev="{f["severity"]}" data-mod="{e(f["module"])}" '
            f'data-status="{f["status"]}" data-conf="{f["confidence"]}" '
            f'data-asset="{e(f["asset"].lower())}" data-text="{e((f["type"] + " " + ev_txt).lower())}">'
            f'<td><span class="sev" style="color:{c};border-color:{c}">{f["severity"].upper()}</span></td>'
            f'<td><span class="st" style="color:{sc};border-color:{sc}">{f["status"]}</span></td>'
            f'<td><span class="cf" style="color:{cc}">{f["confidence"]}</span></td>'
            f'<td>{e(f["module"])}</td><td>{e(f["type"])}</td>'
            f'<td style="color:var(--acc)" class="asset">{e(f["asset"])}</td>'
            f'<td class="mut">{e(ev_txt)}</td></tr>')

    cards = ""
    for sev in ("critical", "high", "medium", "low"):
        n = totals.get(sev, 0)
        if n:
            cards += (f'<div class="stat"><b style="color:{SEV_COLORS[sev]}">{n}</b>'
                      f'<br><span>{sev}</span></div>')
    status_cards = ""
    st_tot = {}
    for f in ctx.findings:
        st_tot[f.status] = st_tot.get(f.status, 0) + 1
    for st in ("finding", "candidate", "observation"):
        if st_tot.get(st):
            status_cards += (f'<div class="stat"><b style="color:{STATUS_COLORS[st]}">'
                             f'{st_tot[st]}</b><br><span>{st}</span></div>')
    if not cards:
        cards = '<div class="stat"><b style="color:#00ff88">0</b><br><span>achados</span></div>'

    mod_cards = ""
    for name, r in results.items():
        stc = {"done": "#00ff88", "err": "#ff0044", "skipped": "#7d8590"}.get(r.status, "#ffaa00")
        stats_html = "".join(
            f'<div><b>{e(str(v))}</b> <span class="mut">{e(str(k))}</span></div>'
            for k, v in list(r.stats.items())[:6])
        mod_cards += f"""
        <div class="mod">
          <div class="modhead">
            <div class="modname">{e(name)}</div>
            <div><span class="badge" style="background:{stc}20;color:{stc};border-color:{stc}">{r.status.upper()}</span>
                 <div class="mut" style="font-size:11px;margin-top:4px">{r.elapsed:.1f}s · {len(r.findings)} achados</div></div>
          </div>
          {f'<div class="mut" style="color:#ff6680;font-size:11px;margin-top:8px">err: {e(r.error)}</div>' if r.error else ''}
          <div class="modstats">{stats_html}</div>
          {(r.stats.get('sources') and ('<details class="srctxt"><summary class="mut">fontes</summary>' + "".join(
              f'<div class="src-line"><span class="src-name">{e(k)}</span> <span class="mut">{e(str(v))}</span></div>'
              for k, v in r.stats["sources"].items()) + '</details>') or '')}
        </div>"""

    data = ctx.data
    assets = data.get("assets") or []
    asset_rows = ""
    for asset in assets[:300]:
        techs = ", ".join(
            f"{name}{(' ' + info['version']) if info.get('version') else ''}"
            for name, info in (asset.get("technologies") or {}).items()) or "-"
        network = ", ".join(asset.get("ips") or [])
        ports = ", ".join(str(p) for p in asset.get("ports") or [])
        if ports:
            network = f"{network} · ports {ports}" if network else f"ports {ports}"
        asset_rows += (
            f'<tr><td style="color:var(--acc)">{e(asset["asset"])}</td>'
            f'<td class="mut">{e(asset["kind"])}</td>'
            f'<td class="mut">{e(network or "-")}</td>'
            f'<td>{e(techs)}</td>'
            f'<td>{len(asset.get("findings") or [])}</td></tr>')
    subs = sorted(data.get("subdomains") or [])[:300]
    subs_html = "".join(f"<li>{e(s)}</li>" for s in subs)
    stack_rows = ""
    for host, techs in list((data.get("stack") or {}).items())[:120]:
        tags = "".join(
            f'<span class="tag">{e(t)}{(chr(32) + techs[t]["version"]) if techs[t].get("version") else ""}</span>'
            for t in sorted(techs))
        stack_rows += f'<tr><td style="color:var(--acc)">{e(host)}</td><td>{tags}</td></tr>'
    bucket_rows = ""
    for b in (data.get("buckets") or []):
        if not b.get("open"):
            continue
        col = "#ff0044" if b["attributed"] else "#ffaa00"
        bucket_rows += (f'<tr><td>{e(b["provider"])}</td>'
                        f'<td style="color:{col};font-weight:bold">{e(b["name"])}</td>'
                        f'<td class="mut">{e(b["url"])}</td></tr>')
    cred_rows = ""
    for cr in (data.get("creds") or [])[:80]:
        pw = cr.get("password", "")
        pw_masked = (pw[:2] + "*" * 10 + pw[-2:]) if len(pw) > 6 else ("*" * len(pw)) \
            if not sensitive else pw
        cred_rows += (f'<tr><td style="color:var(--acc)">{e(cr["email"])}</td>'
                      f'<td class="mut">{e(pw_masked)}</td>'
                      f'<td class="mut">{e(cr.get("source", ""))}</td></tr>')

    blocked_html = ""
    if ctx.scope is not None and ctx.scope.blocked:
        rows_b = "".join(f'<tr><td class="mut">{e(b["url"])}</td>'
                         f'<td style="color:var(--warn)">{e(b["reason"])}</td></tr>'
                         for b in ctx.scope.blocked[:60])
        blocked_html = (f'<h2>Escopo · requisições bloqueadas ({len(ctx.scope.blocked)})</h2>'
                        f'<table><thead><tr><th>url</th><th>motivo</th></tr></thead>'
                        f'<tbody>{rows_b}</tbody></table>')

    baseline_html = ""
    if baseline_diff is not None:
        from .baseline import render_diff
        baseline_html = render_diff(baseline_diff)
    elif getattr(ctx.args, "baseline", None):
        baseline_html = (f'<h2>Baseline</h2><p class="mut">diff calculado '
                         f'contra {e(str(ctx.args.baseline))} — veja '
                         f'scan.json / console.</p>')

    html = f"""<!DOCTYPE html>
<html lang="pt-BR"><head><meta charset="utf-8"><title>{BRAND} :: {e(ctx.domain)}</title>
<style>
:root {{ --bg:#050a14; --bg2:#0a1220; --fg:#f0f6fc; --mut:#7d8590; --acc:#00f0ff;
  --pri:#00f0ff; --ok:#00ff88; --warn:#ffaa00; --err:#ff0044; }}
*{{box-sizing:border-box}}
body {{ margin:0; background:var(--bg); color:var(--fg);
  font-family:'JetBrains Mono','Cascadia Code',Consolas,monospace; font-size:13px;
  background-image:radial-gradient(at 0% 0%,rgba(0,240,255,.08) 0,transparent 45%),
                   radial-gradient(at 100% 0%,rgba(192,132,252,.07) 0,transparent 45%); }}
header {{ padding:30px 34px 22px; border-bottom:1px solid rgba(0,240,255,.25); }}
h1 {{ margin:0; font-size:24px; letter-spacing:3px; color:var(--pri);
  text-shadow:0 0 12px rgba(0,240,255,.5); }}
.meta {{ color:var(--mut); font-size:12px; margin-top:8px; }}
.meta .dom {{ color:var(--acc); font-weight:bold; font-size:15px; }}
.wrap {{ padding:22px 34px; max-width:1500px; margin:0 auto; }}
.statsline {{ display:flex; gap:14px; flex-wrap:wrap; margin-bottom:26px; }}
.stat {{ background:var(--bg2); border:1px solid rgba(125,133,144,.18);
  padding:12px 18px; border-radius:10px; text-align:center; min-width:105px; }}
.stat b {{ font-size:24px; }} .stat span {{ color:var(--mut); font-size:11px; }}
h2 {{ color:var(--pri); font-size:13px; letter-spacing:2px; text-transform:uppercase;
  margin:34px 0 12px; padding-bottom:8px; border-bottom:1px solid rgba(0,240,255,.25); }}
table {{ width:100%; border-collapse:collapse; margin-bottom:20px;
  background:rgba(255,255,255,.015); border-radius:8px; overflow:hidden; }}
th {{ text-align:left; padding:9px 12px; font-size:10px; letter-spacing:1px;
  text-transform:uppercase; color:var(--mut); border-bottom:1px solid rgba(125,133,144,.25); cursor:pointer; }}
td {{ padding:7px 12px; font-size:12px; border-bottom:1px solid rgba(125,133,144,.09);
  word-break:break-all; }}
tr.row:hover td {{ background:rgba(0,240,255,.04); }}
.mut {{ color:var(--mut); }}
.sev,.st {{ display:inline-block; padding:1px 8px; border:1px solid; border-radius:4px;
  font-size:10px; font-weight:bold; letter-spacing:1px; text-transform:uppercase; }}
.cf {{ font-weight:bold; font-size:11px; }}
#controls {{ display:flex; gap:10px; flex-wrap:wrap; margin-bottom:14px;
  position:sticky; top:0; background:var(--bg); padding:10px 0; z-index:5; }}
#q {{ flex:1; min-width:220px; background:var(--bg2); color:var(--fg);
  border:1px solid rgba(0,240,255,.3); border-radius:6px; padding:8px 12px;
  font-family:inherit; font-size:12px; }}
.chip {{ background:var(--bg2); border:1px solid rgba(125,133,144,.3);
  color:var(--fg); border-radius:14px; padding:4px 12px; cursor:pointer;
  font-family:inherit; font-size:11px; }}
.chip.on {{ border-color:var(--acc); color:var(--acc); }}
.mods {{ display:grid; grid-template-columns:repeat(auto-fill,minmax(320px,1fr)); gap:14px; }}
.mod {{ background:linear-gradient(180deg,var(--bg2),var(--bg));
  border:1px solid rgba(0,240,255,.18); border-radius:10px; padding:16px 18px; }}
.modhead {{ display:flex; justify-content:space-between; align-items:flex-start; }}
.modname {{ font-weight:bold; font-size:15px; color:var(--pri); }}
.badge {{ padding:2px 9px; border-radius:4px; font-size:10px; border:1px solid;
  font-weight:bold; letter-spacing:1px; }}
.modstats {{ display:grid; grid-template-columns:repeat(2,1fr); gap:5px 12px;
  font-size:11px; margin-top:12px; border-top:1px solid rgba(125,133,144,.15); padding-top:10px; }}
.srctxt {{ margin-top:10px; }} .srctxt summary {{ cursor:pointer; font-size:11px; }}
.src-line {{ font-size:11px; margin-top:3px; }}
.src-name {{ color:var(--acc); }}
.tag {{ display:inline-block; background:rgba(0,240,255,.08); color:var(--acc);
  border:1px solid rgba(0,240,255,.25); padding:1px 7px; border-radius:4px;
  font-size:10px; margin:2px 3px 2px 0; }}
.diff-new {{ color:#ff6680; font-weight:bold; }}
.diff-resolved {{ color:#00ff88; }}
.diff-changed {{ color:#ffaa00; }}
footer {{ padding:28px 34px; color:var(--mut); font-size:11px; text-align:center;
  border-top:1px solid rgba(125,133,144,.15); margin-top:44px; }}
ul.subs {{ columns:3; column-gap:30px; max-height:420px; overflow-y:auto; font-size:12px; }}
ul.subs li {{ margin-bottom:3px; color:#b8c4d0; }}
</style></head><body>
<header>
  <h1>{BRAND}</h1>
  <div class="meta">v{__version__} · target: <span class="dom">{e(ctx.domain)}</span>
   · {now} · elapsed {ctx.elapsed:.0f}s · scan {ctx.id}
   {'· <span style="color:var(--warn)">SENSÍVEL: valores completos</span>' if sensitive else '· valores mascarados (--include-sensitive p/ completo)'}</div>
</header>
<div class="wrap">
<div class="statsline">{cards}{status_cards}<div class="stat"><b style="color:var(--acc)">{len(assets)}</b><br><span>ativos</span></div></div>

<h2>Módulos</h2><div class="mods">{mod_cards}</div>

<h2>Achados ({len(rows_data)})</h2>
<div id="controls">
  <input id="q" placeholder="buscar em achados (tipo, evidência, ativo)..." />
  <button class="chip sevchip on" data-v="">sev: todas</button>
  <button class="chip sevchip" data-v="critical">critical</button>
  <button class="chip sevchip" data-v="high">high</button>
  <button class="chip sevchip" data-v="medium">medium</button>
  <button class="chip stchip on" data-v="">status: todos</button>
  <button class="chip stchip" data-v="finding">finding</button>
  <button class="chip stchip" data-v="candidate">candidate</button>
  <button class="chip stchip" data-v="observation">observation</button>
  <button class="chip cfchip on" data-v="">conf: toda</button>
  <button class="chip cfchip" data-v="high">conf high</button>
  <button class="chip grp" data-on="0">agrupar por ativo</button>
</div>
<table id="ftable"><thead><tr>
<th>severidade</th><th>status</th><th>conf.</th><th>módulo</th><th>tipo</th>
<th>ativo</th><th>evidência</th></tr></thead>
<tbody>{findings_rows or '<tr><td colspan="7" class="mut">nenhum achado.</td></tr>'}</tbody></table>

{baseline_html}

{asset_rows and '<h2>Inventário correlacionado de ativos</h2><table><thead><tr><th>ativo</th><th>tipo</th><th>rede</th><th>tecnologias</th><th>achados</th></tr></thead><tbody>' + asset_rows + '</tbody></table>' or ''}
{stack_rows and '<h2>Tecnologias (stack)</h2><table><thead><tr><th>host</th><th>techs</th></tr></thead><tbody>' + stack_rows + '</tbody></table>' or ''}
{bucket_rows and '<h2>Buckets abertos</h2><table><thead><tr><th>provider</th><th>bucket</th><th>url</th></tr></thead><tbody>' + bucket_rows + '</tbody></table>' or ''}
{cred_rows and '<h2>Credenciais vazadas</h2><table><thead><tr><th>email</th><th>senha</th><th>fonte</th></tr></thead><tbody>' + cred_rows + '</tbody></table>' or ''}
{blocked_html}
{subs_html and f'<h2>Subdomínios ({len(subs)}+)</h2><ul class="subs">{subs_html}</ul>' or ''}

</div>
<footer>{BRAND} v{__version__} · scan {ctx.id} · coletado {now}</footer>
<script>
const q=document.getElementById('q');
let sevF='',stF='',cfF='',grp=false;
function apply(){{
 const t=q.value.toLowerCase();
 document.querySelectorAll('#ftable tbody tr.row').forEach(tr=>{{
  const ok=(t===''||tr.dataset.text.includes(t)||tr.dataset.asset.includes(t))
   &&(!sevF||tr.dataset.sev===sevF)&&(!stF||tr.dataset.status===stF)&&(!cfF||tr.dataset.conf===cfF);
  tr.style.display=ok?'':'none';}});
}}
function chip(sel,cb){{document.querySelectorAll(sel).forEach(b=>b.onclick=()=>{{
 document.querySelectorAll(sel).forEach(x=>x.classList.remove('on'));b.classList.add('on');cb(b.dataset.v);apply();}});}}
chip('.sevchip',v=>sevF=v);chip('.stchip',v=>stF=v);chip('.cfchip',v=>cfF=v);
document.querySelector('.grp').onclick=function(){{grp=!grp;this.classList.toggle('on',grp);
 const tb=document.querySelector('#ftable tbody');
 const rows=[...tb.querySelectorAll('tr.row')];
 if(grp){{rows.sort((a,b)=>a.dataset.asset.localeCompare(b.dataset.asset));}}
 else{{rows.sort((a,b)=>a.rowIndex-b.rowIndex);}}
 rows.forEach(r=>tb.appendChild(r));}};
q.oninput=apply;
document.querySelectorAll('#ftable th').forEach((th,i)=>th.style.cursor='default');
</script>
</body></html>"""
    (ctx.out_dir / "report.html").write_text(html, encoding="utf-8")
