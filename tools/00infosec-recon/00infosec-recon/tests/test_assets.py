from __future__ import annotations

import json
from argparse import Namespace
from pathlib import Path

from infosec_recon.cli import build_parser, fail_threshold_reached, parse_args_with_config
from infosec_recon.core.models import ModuleResult, ScanContext
from infosec_recon.report.assets import build_asset_inventory
from infosec_recon.report.baseline import diff_scans
from infosec_recon.report.html import build_html, write_scan_json
from infosec_recon.report.markdown import write_markdown
from infosec_recon.runner import _write_assets_jsonl


def _context(tmp_path: Path) -> ScanContext:
    ctx = ScanContext("example.com", tmp_path, Namespace(include_sensitive=False))
    ctx.data = {
        "subdomains": {"api.example.com"},
        "hosts_alive": {"api.example.com"},
        "dns_records": [{"host": "api.example.com", "alive": True,
                         "A": ["203.0.113.10"], "AAAA": [],
                         "CNAME": ["origin.example.com"]}],
        "http_records": [{"host": "api.example.com", "url": "https://api.example.com/",
                          "status": 200, "title": "API", "server": "nginx"}],
        "stack": {"api.example.com": {"nginx": {
            "version": "1.24", "category": "web-server"}}},
        "internetdb": {"203.0.113.10": {"ports": [443, 8443]}},
        "cves": [{"id": "CVE-2024-1111", "matched_hosts": ["api.example.com"]}],
        "endpoints": [{"endpoint": "/v1/users",
                       "found_in": "https://api.example.com/app.js"}],
        "buckets": [{"provider": "aws-s3", "name": "example-backup",
                     "url": "https://example-backup.s3.amazonaws.com/",
                     "open": True, "attributed": True}],
    }
    result = ModuleResult("recon")
    result.add("open_port", "low", "203.0.113.10", evidence={"port": 8443})
    ctx.findings = list(result.findings)
    return ctx


def test_asset_inventory_correlates_host_ip_service_and_findings(tmp_path):
    ctx = _context(tmp_path)
    assets = build_asset_inventory(ctx)
    by_name = {a["asset"]: a for a in assets}

    host = by_name["api.example.com"]
    assert host["alive"] is True
    assert host["ips"] == ["203.0.113.10"]
    assert host["technologies"]["nginx"]["version"] == "1.24"
    assert host["cves"] == ["CVE-2024-1111"]
    assert host["endpoints"] == ["/v1/users"]

    ip = by_name["203.0.113.10"]
    assert ip["hosts"] == ["api.example.com"]
    assert ip["ports"] == [443, 8443]
    assert ip["findings"][0]["type"] == "open_port"
    assert by_name["example.com"]["cloud"][0]["name"] == "example-backup"


def test_asset_outputs_are_written_and_masked(tmp_path):
    ctx = _context(tmp_path)
    ctx.data["assets"] = build_asset_inventory(ctx)
    result = ModuleResult("recon")
    result.finish("done")

    doc = write_scan_json(ctx, {"recon": result})
    assert doc["assets"] and doc["source_health"]["recon"]["status"] == "done"
    _write_assets_jsonl(ctx, include_sensitive=False)
    write_markdown(ctx, {"recon": result})
    build_html(ctx, {"recon": result})

    rows = (tmp_path / "assets.jsonl").read_text("utf-8").splitlines()
    assert len(rows) == len(ctx.data["assets"])
    assert "api.example.com" in (tmp_path / "report.md").read_text("utf-8")
    assert "Inventário correlacionado" in (tmp_path / "report.html").read_text("utf-8")


def test_baseline_detects_ports_and_service_changes():
    previous = {"assets": [{"asset": "api.example.com", "kind": "subdomain",
                            "ports": [443], "urls": [{"url": "https://api.example.com/",
                                                       "status": 200, "server": "nginx"}]}]}
    current = {"assets": [{"asset": "api.example.com", "kind": "subdomain",
                           "ports": [443, 8443], "urls": [{"url": "https://api.example.com/",
                                                            "status": 503, "server": "nginx"}]}]}
    diff = diff_scans(current, previous)
    assert any("8443" in item for item in diff["new"])
    assert any("api.example.com" in item["what"] for item in diff["changed"])


def test_json_config_and_fail_on(tmp_path):
    config = tmp_path / "config.json"
    config.write_text(json.dumps({"profile": "quick", "concurrency": 7,
                                  "fail-on": "high", "passive": True}), "utf-8")
    args = parse_args_with_config(
        build_parser(), ["--config", str(config), "example.com", "--concurrency", "9"])
    assert args.profile == "quick" and args.passive is True
    assert args.concurrency == 9 and args.fail_on == "high"

    ctx = _context(tmp_path)
    high = ModuleResult("demo")
    high.add("demo", "high", "api.example.com")
    ctx.findings = high.findings
    assert fail_threshold_reached(ctx, "high") is True
    assert fail_threshold_reached(ctx, "critical") is False
