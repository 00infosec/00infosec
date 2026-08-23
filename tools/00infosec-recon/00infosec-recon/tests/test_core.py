"""Core unit tests. Runs under pytest OR directly: python tests/test_core.py"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from infosec_recon.core.models import ModuleResult, ScanContext, severity_from_cvss
from infosec_recon.core.net import (
    extract_hosts_from_text,
    normalize_host,
    registrable_core,
    sanitize_slug,
    split_registrable,
)
from infosec_recon.modules.cloudhunt import generate_permutations
from infosec_recon.modules.cvescan import STACK_CPE_MAP, parse_nvd, version_satisfies
from infosec_recon.modules.phishlab import generate_typosquats

# ---------------------------------------------------------------- core/net

def test_split_registrable_compound_suffix():
    assert split_registrable("banpara.b.br") == ("banpara", "b.br")
    assert split_registrable("www.banpara.b.br") == ("banpara", "b.br")
    assert split_registrable("bancoamazonia.com.br") == ("bancoamazonia", "com.br")
    assert registrable_core("example.com") == "example"


def test_normalize_host():
    assert normalize_host("WWW.Example.com.", "example.com") == "www.example.com"
    assert normalize_host("*.example.com", "example.com") == "example.com"
    assert normalize_host("evil.com", "example.com") is None
    assert normalize_host("sub.example.com", "example.com") == "sub.example.com"
    assert normalize_host("https://a.example.com/x", "example.com") == \
        "a.example.com"


def test_extract_hosts_from_text():
    txt = 'x a1.example.com y http://b2.example.com/z not@outsider.org'
    hosts = extract_hosts_from_text(txt, "example.com")
    assert hosts == {"a1.example.com", "b2.example.com"}


def test_sanitize_slug():
    assert sanitize_slug("Example.COM.br") == "example.com.br"


def test_severity_from_cvss():
    assert severity_from_cvss(9.8) == "critical"
    assert severity_from_cvss(7.0) == "high"
    assert severity_from_cvss(4.1) == "medium"
    assert severity_from_cvss(0.5) == "low"
    assert severity_from_cvss(None) == "unknown"


# ---------------------------------------------------------------- cvescan

def test_version_gate():
    assert version_satisfies("2.4.49", {"end_inc": "2.4.50"}) is True
    assert version_satisfies("2.4.51", {"end_inc": "2.4.50"}) is False
    assert version_satisfies("1.2", {"start_exc": "1.0",
                                     "end_exc": "1.5"}) is True
    assert version_satisfies("1.7", {"start_exc": "1.0",
                                     "end_exc": "1.5"}) is False
    assert version_satisfies("9.9", {}) is None


def test_stack_cpe_map_sane():
    for k, v in STACK_CPE_MAP.items():
        assert isinstance(v, tuple) and len(v) == 2, k


def test_parse_nvd_minimal():
    cve = {
        "id": "CVE-2024-1234",
        "descriptions": [{"lang": "en", "value": "boom"}],
        "metrics": {"cvssMetricV31": [{"cvssData": {
            "baseScore": 9.8, "baseSeverity": "CRITICAL",
            "vectorString": "CVSS:3.1/AV:N"}}]},
        "weaknesses": [{"description": [{"value": "CWE-79"}]}],
        "configurations": [{"nodes": [{"cpeMatch": [
            {"criteria": "cpe:2.3:a:x:y:1.0:*:*:*:*:*:*:*",
             "versionEndIncluding": "1.0"}]}]}],
        "references": [{"url": "https://x"}],
    }
    p = parse_nvd(cve)
    assert p["id"] == "CVE-2024-1234" and p["cvss"] == 9.8
    assert p["cwes"] == ["CWE-79"]
    assert p["affected"][0]["end_inc"] == "1.0"


# ---------------------------------------------------------------- cloudhunt

def test_generate_permutations():
    perms = generate_permutations("banpara.b.br", max_perms=100)
    assert "banpara-prod" in perms or "prod-banpara" in perms
    assert all(3 <= len(p) <= 63 for p in perms)
    assert len(perms) <= 100


# ---------------------------------------------------------------- phishlab

def test_typosquats_exclude_self():
    variants = generate_typosquats("example.com", max_per_method=30)
    assert "example.com" not in variants
    assert len(variants) > 20
    assert any(v.endswith(".net") for v in variants)


# ---------------------------------------------------------------- models

def test_merge_findings_dedup():
    ctx = ScanContext("example.com", Path(tempfile.mkdtemp()), object())
    r1 = ModuleResult("recon")
    r1.add("exposed_file", "critical", "h.example.com", evidence="/.env")
    r2 = ModuleResult("jsleak")
    r2.add("exposed_file", "critical", "h.example.com", evidence="/.env")
    r2.add("js_secret", "high", "u.js", evidence="aws=AKIA...")
    ctx.merge_findings(r1)
    ctx.merge_findings(r2)
    types = sorted(f.type for f in ctx.findings)
    assert types == ["exposed_file", "js_secret"], types


def test_checkpoint_roundtrip(tmp_path=None):
    from infosec_recon.runner import load_checkpoint, save_checkpoint
    tmp = Path(tempfile.mkdtemp())
    ctx = ScanContext("example.com", tmp, object())
    modules = {"recon": object()}
    r = ModuleResult("recon")
    r.status = "done"
    r.stats["subdomains"] = 42
    r.add("exposed_file", "critical", "h.x", evidence="/.git/config",
          source="probe", extra_key="v")
    save_checkpoint(ctx, modules, results_partial={"recon": r})

    loaded = load_checkpoint(tmp / "checkpoint.json", {"recon"})
    assert set(loaded) == {"recon"}
    lr = loaded["recon"]
    assert lr.status == "done" and lr.stats["subdomains"] == 42
    f = lr.findings[0]
    assert f.evidence.get("summary") == "/.git/config"
    assert f.evidence.get("extra_key") == "v"
    assert f.asset == "h.x" and f.status == "finding"

    empty = load_checkpoint(tmp / "missing.json", {"recon"})
    assert empty == {}


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
    sys.exit(1 if fails else 0)
