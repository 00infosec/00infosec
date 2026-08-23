from __future__ import annotations

from html import escape as e


def _finding_identity(fd: dict) -> tuple:
    ev = fd.get("evidence") or {}
    for k in ("path", "url", "cve", "breach"):
        if ev.get(k):
            return (fd.get("type"), fd.get("asset"), str(ev[k]))
    s = ev.get("summary")
    return (fd.get("type"), fd.get("asset"), str(s)[:120] if s else "")


def _collect(doc: dict) -> tuple[set, dict, dict, dict]:
    """Collect identities plus comparable CVE, stack and service state."""
    keys: set = set()
    for r in (doc.get("results") or {}).values():
        for fd in r.get("findings") or []:
            if fd.get("status") in ("finding", "candidate"):
                keys.add(_finding_identity(fd))
    sev: dict[str, str] = {}
    stack: dict[str, str] = {}
    services: dict[str, str] = {}
    surface = doc.get("surface") or {}
    subs = set(surface.get("subdomains") or ())
    alive = set()
    for c in surface.get("cves") or []:
        sev[c["id"]] = c.get("severity") or ""
    for host, techs in (surface.get("stack") or {}).items():
        for t, v in techs.items():
            stack[f"{host}|{t}"] = v or ""
    for h in surface.get("alive") or []:
        alive.add(h)
    for asset in doc.get("assets") or []:
        name = asset.get("asset")
        if not name:
            continue
        keys.add(("asset", name, asset.get("kind") or ""))
        for port in asset.get("ports") or []:
            keys.add(("open_port", name, str(port)))
        for http in asset.get("urls") or []:
            url = http.get("url")
            if url:
                services[f"{name}|{url}"] = \
                    f"{http.get('status', '')}|{http.get('server', '')}"
    return keys | {("subdomain", s, "") for s in subs} | \
        {("alive_host", h, "") for h in alive}, sev, stack, services


def diff_scans(current: dict, previous: dict) -> dict:
    cur_keys, cur_sev, cur_stack, cur_services = _collect(current)
    prev_keys, prev_sev, prev_stack, prev_services = _collect(previous)

    new = sorted(cur_keys - prev_keys)
    resolved = sorted(prev_keys - cur_keys)

    changed = []
    for k in sorted(set(cur_sev) & set(prev_sev)):
        if cur_sev[k] != prev_sev[k]:
            changed.append({"what": f"CVE {k}", "from": prev_sev[k],
                            "to": cur_sev[k]})
    for k in sorted(set(cur_stack) & set(prev_stack)):
        if cur_stack[k] != prev_stack[k]:
            changed.append({"what": f"{k.split('|', 1)[0]} · "
                                    f"{k.split('|', 1)[1]}",
                            "from": prev_stack[k] or "-",
                            "to": cur_stack[k] or "-"})
    for k in sorted(set(cur_services) & set(prev_services)):
        if cur_services[k] != prev_services[k]:
            asset, url = k.split("|", 1)
            changed.append({"what": f"{asset} · {url}",
                            "from": prev_services[k] or "-",
                            "to": cur_services[k] or "-"})

    def fmt(keys, cls):
        out = []
        for t, asset, ev in keys[:400]:
            label = asset
            if t == "subdomain":
                label = asset
            elif ev and ev not in ("", "None"):
                label = f"{asset} — {ev}"
            out.append(f'<div class="{cls}">{e(t.upper())} · {e(label)}</div>')
        return "".join(out) or '<div class="mut">nenhum</div>'

    changed_html = "".join(
        f'<div class="diff-changed">{e(c["what"])}: '
        f'{e(str(c["from"]))} → {e(str(c["to"]))}</div>'
        for c in changed[:200]) or '<div class="mut">nada alterado</div>'

    return {
        "new_count": len(new), "resolved_count": len(resolved),
        "changed_count": len(changed),
        "new": [f"{t} · {a}" + (f" · {ev_}" if ev_ else "")
                for t, a, ev_ in new[:400]],
        "resolved": [f"{t} · {a}" + (f" · {ev_}" if ev_ else "")
                     for t, a, ev_ in resolved[:400]],
        "changed": changed,
        "html": (
            "<h2>Baseline · diferenças</h2>"
            f'<div class="diffbox">'
            f'<h3 style="color:#ff6680;margin:8px 0 4px">NOVO ({len(new)})</h3>{fmt(new, "diff-new")}'
            f'<h3 style="color:#00ff88;margin:14px 0 4px">RESOLVIDO ({len(resolved)})</h3>{fmt(resolved, "diff-resolved")}'
            f'<h3 style="color:#ffaa00;margin:14px 0 4px">ALTERADO ({len(changed)})</h3>{changed_html}'
            "</div>"),
    }


def render_diff(diff: dict) -> str:
    return diff.get("html", "")
