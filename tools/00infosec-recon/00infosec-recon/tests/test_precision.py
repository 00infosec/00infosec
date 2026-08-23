"""Precision & safety regression tests. Runs under pytest or standalone."""
from __future__ import annotations

import asyncio
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from infosec_recon.cli import PROFILES, build_parser, parse_duration, resolve_modules
from infosec_recon.core.http import parse_retry_after
from infosec_recon.core.redact import mask_record
from infosec_recon.core.scope import Scope, validate_domain
from infosec_recon.modules.cvescan import CveScanModule, parse_osv_item


def _module():
    """CveScanModule with network deps stubbed out (correlate/emit are pure)."""
    return CveScanModule(ctx=None, http=None, dns=None, cfg=None,
                         console=None)


def _cve(cid="CVE-2024-1111", desc="nginx flaw", cvss=9.8):
    return {"id": cid, "cvss": cvss, "description": desc, "kev": False,
            "exploitdb_ids": [], "sources": ["nvd"], "severity": "critical",
            "cpes": ["cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*"],
            "affected": []}


def _hit(version=None, hosts=("h1.example.com",)):
    return {"vendor": "nginx", "product": "nginx", "version": version,
            "tech": "nginx", "hosts": list(hosts)}


# 1. KEV sem correlação não vira finding ------------------------------------

def test_kev_without_correlation_is_not_finding():
    m = _module()
    c = _cve()
    c["kev"] = True
    host_map = m.correlate({"X": c}, hits=[])          # nenhum produto no stack
    m.emit_findings([c])
    assert not host_map and not m.result.findings


# 2. CVE com produto + versão compatível vira finding high ------------------

def test_cve_with_version_becomes_high_confidence_finding():
    m = _module()
    c = _cve(desc="")
    c["affected"] = [{"cpe": "cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*",
                      "start_inc": None, "start_exc": None,
                      "end_inc": "1.24.0", "end_exc": None}]
    c["cpes"] = ["cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*"]
    h = _hit(version="1.24.0")
    m.correlate({"X": c}, [h])
    assert c["matched_hosts"] == ["h1.example.com"]
    assert c["correlation_basis"] == "cpe+version"
    m.emit_findings([c])
    f = m.result.findings[0]
    assert f.status == "finding" and f.confidence == "high"
    assert f.asset == "h1.example.com"


def test_cve_product_only_is_candidate_medium():
    m = _module()
    c = _cve()                                          # sem faixas affected
    h = _hit(version=None)
    m.correlate({c["id"]: c}, [h])
    m.emit_findings([c])
    f = m.result.findings[0]
    assert f.status == "candidate" and f.confidence == "medium"


def test_keyword_only_match_is_candidate_low():
    m = _module()
    c = _cve(desc="something about nginx somewhere")
    c["cpes"] = []
    h = _hit()
    m.correlate({c["id"]: c}, [h])
    m.emit_findings([c])
    f = m.result.findings[0]
    assert f.status == "candidate" and f.confidence == "low"


def test_kev_enriches_correlated_but_not_uncorrelated():
    m = _module()
    uncorrelated = _cve("CVE-2024-9999")
    uncorrelated["kev"] = True
    correlated = _cve("CVE-2024-1111")
    correlated["kev"] = True
    m.correlate({correlated["id"]: correlated}, [_hit()])
    m.correlate({uncorrelated["id"]: uncorrelated}, [])
    m.emit_findings([correlated, uncorrelated])
    assert len(m.result.findings) == 1
    ev = m.result.findings[0].evidence
    assert ev["kev"] is True and ev["basis"] in ("cpe", "cpe+version")


# 3. OSV ---------------------------------------------------------------------

def test_osv_alias_to_cve():
    it = {"id": "GHSA-xxxx-yyyy-zzzz",
          "aliases": ["CVE-2024-2222"],
          "summary": "bad pkg",
          "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/7.5"}]}
    p = parse_osv_item(it)
    assert p["id"] == "CVE-2024-2222" and p["cvss"] == 7.5


def test_osv_ghsa_only_is_dropped():
    assert parse_osv_item({"id": "GHSA-a-b-c"}) is None


def test_osv_parses_httpclient_response_body():
    class Response:
        body = json.dumps({"vulns": [{
            "id": "GHSA-a-b-c", "aliases": ["CVE-2024-3333"],
            "summary": "package flaw",
        }]})

    class Http:
        async def post(self, url, *, json_body, timeout):
            assert json_body == {"package": {"name": "demo", "ecosystem": "PyPI"}}
            return Response()

    m = CveScanModule(ctx=None, http=Http(), dns=None, cfg=None, console=None)
    assert asyncio.run(m.src_osv("demo", "PyPI")) == [{
        "id": "CVE-2024-3333", "cvss": None, "description": "package flaw"}]


def test_kev_catalog_does_not_seed_scan_cves_or_epss():
    class Ctx:
        data = {"stack": {"app.example.com": {"nginx": {"version": "1.24"}}}}
        args = type("Args", (), {"quick_nvd": True})()

    cfg = type("Cfg", (), {"gh_token": None})()
    m = CveScanModule(ctx=Ctx(), http=None, dns=None, cfg=cfg, console=None)
    observed_epss = []

    async def kev(meta):
        meta["CVE-2099-9999"] = {"name": "unrelated"}
        return [{"id": "CVE-2099-9999", "description": "unrelated"}]

    async def nvd(*_args):
        return [{"id": "CVE-2024-1111", "cvss": 7.5,
                 "description": "nginx flaw", "cpes": [
                     "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*"],
                 "affected": []}]

    async def empty(*_args):
        return []

    async def epss(ids):
        observed_epss.extend(ids)
        return {}

    m.src_kev, m.nvd_by_cpe, m.src_circl = kev, nvd, empty
    m.src_exploitdb, m.src_epss = empty, epss
    asyncio.run(m.run())
    assert [c["id"] for c in m.ctx.data["cves"]] == ["CVE-2024-1111"]
    assert observed_epss == ["CVE-2024-1111"]


# 4. Escopo / anti-SSRF -------------------------------------------------------

def test_invalid_domain_rejected():
    for bad in ("not a domain!", "-x.com", "a..b", "http://", ""):
        try:
            validate_domain(bad)
            raise AssertionError(f"aceitou {bad!r}")
        except ValueError:
            pass
    assert validate_domain("example.com") == "example.com"


def test_external_url_blocked_in_scope():
    sc = Scope(domain="example.com")
    ok, why = sc.url_allowed("https://evil.com/x")
    assert not ok and why == "fora_do_escopo"
    ok, why = sc.url_allowed("https://sub.example.com/a.js")
    assert ok


def test_private_ips_blocked():
    sc = Scope(domain="example.com")
    assert sc.ip_allowed("10.0.0.5")[0] is False
    assert sc.ip_allowed("127.0.0.1")[0] is False
    assert sc.ip_allowed("169.254.169.254")[0] is False   # metadata AWS
    assert sc.ip_allowed("8.8.8.8")[0] is True
    priv = Scope(domain="example.com", allow_private_ips=True)
    assert priv.ip_allowed("192.168.1.10")[0] is True
    assert priv.ip_allowed("127.0.0.1")[0] is False       # loopback segue bloqueado


def test_redirect_out_of_scope_blocked(monkeypatch=None):
    sc = Scope(domain="example.com")
    ok, why = sc.url_allowed("https://cdn.evil.net/payload")
    assert not ok


# 5. Mascaramento --------------------------------------------------------------

def test_secrets_are_masked():
    rec = {"type": "js_secret", "evidence": {
        "value": "AKIAIOSFODNN7EXAMPLE", "context": "token=SuperSecret123!"}}
    masked = mask_record(rec, include_sensitive=False)
    raw = json.dumps(masked)
    assert "AKIAIOSFODNN7EXAMPLE" not in raw
    assert "SuperSecret123!" not in raw
    full = mask_record(rec, include_sensitive=True)
    assert full["evidence"]["value"] == "AKIAIOSFODNN7EXAMPLE"


def test_mcp_persistence_and_rehydration_are_redacted():
    from infosec_recon import mcp_server

    with tempfile.TemporaryDirectory() as td:
        prior = dict(mcp_server.SCANS)
        mcp_server.SCANS.clear()
        try:
            raw = "AKIAIOSFODNN7EXAMPLE"
            entry = {
                "domain": "example.com", "status": "done", "started": 1,
                "finished": 2, "store_root": td,
                "results": {"jsleak": {"status": "done", "elapsed_seconds": 1,
                    "stats": {}, "findings": [{"module": "jsleak",
                        "type": "js_secret", "severity": "high",
                        "evidence": {"value": raw}, "asset": "app.example.com"}]}},
                "data_summary": {"secrets": [{"value": raw}]},
            }
            mcp_server.SCANS["saved"] = entry
            mcp_server._persist_scan("saved", entry)
            persisted = (Path(td) / ".scans" / "saved.json").read_text("utf-8")
            assert raw not in persisted

            # Simulates memory eviction (or a new server with the same out_dir).
            mcp_server.SCANS.clear()
            response = asyncio.run(mcp_server.get_findings("saved", out_dir=td))
            assert raw not in response and "CVE" not in response
            summary = asyncio.run(mcp_server.get_scan_data("saved", out_dir=td))
            assert raw not in summary
        finally:
            mcp_server.SCANS.clear()
            mcp_server.SCANS.update(prior)


def test_retry_after_parsed():
    assert parse_retry_after("7") == 7.0
    assert parse_retry_after(None) is None
    assert parse_retry_after("garbage") is None


# 6. CLI ------------------------------------------------------------------------

def test_list_modules_works_without_domain():
    p = build_parser()
    args = p.parse_args(["--list-modules"])
    assert args.list_modules and args.domain == []


def test_deep_profile_activates_all():
    assert PROFILES["deep"] == set(
        ["recon", "cvescan", "jsleak", "leakhunt", "cloudhunt", "phishlab"])
    args = build_parser().parse_args(["example.com", "-p", "deep"])
    assert args.profile == "deep"


def test_unknown_module_errors():
    args = build_parser().parse_args(["example.com", "--only", "recon,nope"])
    try:
        resolve_modules(args)
        raise AssertionError("deveria ter rejeitado modulo desconhecido")
    except ValueError as e:
        assert "nope" in str(e)


def test_passive_profile_excludes_active_modules():
    args = build_parser().parse_args(["example.com", "-p", "passive"])
    mods = set(resolve_modules(args))
    assert mods <= {"recon", "leakhunt", "phishlab"}
    assert "cloudhunt" not in mods and "jsleak" not in mods


def test_duration_parsing():
    assert parse_duration("20m") == 1200
    assert parse_duration("90s") == 90
    assert parse_duration("2h") == 7200
    assert parse_duration("0") == 0
    try:
        parse_duration("abc")
        raise AssertionError()
    except ValueError:
        pass


# 7. Determinismo -----------------------------------------------------------------

def test_results_deterministic():
    from infosec_recon.modules.cloudhunt import generate_permutations
    from infosec_recon.modules.phishlab import generate_typosquats
    p1 = generate_permutations("banpara.b.br", 100)
    p2 = generate_permutations("banpara.b.br", 100)
    t1 = sorted(generate_typosquats("example.com"))
    t2 = sorted(generate_typosquats("example.com"))
    assert p1 == p2 and t1 == t2


if __name__ == "__main__":
    fails = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"PASS {name}")
            except AssertionError as e:
                fails += 1
                print(f"FAIL {name}: {e}")
            except Exception as e:
                fails += 1
                print(f"ERROR {name}: {type(e).__name__}: {e}")
    sys.exit(1 if fails else 0)
