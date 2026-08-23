from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

SEV_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
CONF_ORDER = {"low": 0, "medium": 1, "high": 2}

STATUSES = ("observation", "candidate", "finding")


def severity_from_cvss(score: Optional[float]) -> str:
    if score is None:
        return "unknown"
    s = float(score)
    if s >= 9.0:
        return "critical"
    if s >= 7.0:
        return "high"
    if s >= 4.0:
        return "medium"
    if s > 0:
        return "low"
    return "none"


REMEDIATIONS = {
    "exposed_file": "Remova o arquivo da raiz pública e investigue possível vazamento.",
    "js_secret": "Rotacione a credencial exposta e remova-a do bundle.",
    "vulnerable_cve": "Atualize o componente para uma versão corrigida.",
    "cloud_bucket_open": "Desative acesso público e aplique bucket policy restritiva.",
    "subdomain_takeover": "Reivindique ou remova o registro DNS do serviço não configurado.",
    "leaked_credential": "Invalide a senha exposta e force redefinição.",
    "open_port": "Restrinja a exposição via firewall se o serviço não for público.",
    "internetdb_cve": "Confirme a versão do serviço exposto e aplique a correção.",
    "phishing_infra": "Monitore o domínio e avalie takedown junto ao registrador.",
    "github_leak": "Revogue o segredo e limpe o histórico do repositório.",
    "source_map_exposed": "Não publique source maps em produção.",
    "data_breach": "Force redefinição de senhas dos usuários afetados.",
}


@dataclass
class Finding:
    module: str
    type: str
    severity: str
    asset: str
    status: str = "finding"
    confidence: str = "medium"
    evidence: dict = field(default_factory=dict)
    source: str = ""
    remediation: str = ""
    collected_at: str = ""

    def to_dict(self) -> dict:
        return {
            "module": self.module,
            "type": self.type,
            "status": self.status,
            "severity": self.severity,
            "confidence": self.confidence,
            "asset": self.asset,
            "evidence": self.evidence,
            "source": self.source,
            "remediation": self.remediation,
            "collected_at": self.collected_at,
        }


@dataclass
class HostRecord:
    host: str
    ips: list = field(default_factory=list)
    cnames: list = field(default_factory=list)
    alive: bool = False
    wildcard_fp: bool = False


@dataclass
class HttpRecord:
    host: str
    url: str = ""
    status: int = 0
    title: str = ""
    scheme: str = ""
    server: str = ""
    stack: dict = field(default_factory=dict)
    content_length: int = 0
    exposed_files: list = field(default_factory=list)
    waf: list = field(default_factory=list)
    security_missing: list = field(default_factory=list)
    tls_san: list = field(default_factory=list)


class ModuleResult:
    def __init__(self, module_name: str):
        self.module = module_name
        self.started = time.time()
        self.ended: Optional[float] = None
        self.status = "queued"
        self.error: Optional[str] = None
        self.stats: dict = {}
        self.findings: list[Finding] = []

    @property
    def elapsed(self) -> float:
        return (self.ended or time.time()) - self.started

    def finish(self, status: str, error: str | None = None):
        self.status = status
        self.error = error
        self.ended = time.time()

    def add(
        self,
        type_: str,
        severity: str,
        asset: str,
        *,
        evidence: Any = None,
        source: str = "",
        status: str = "finding",
        confidence: str = "medium",
        remediation: str = "",
        **extra,
    ) -> Finding:
        ev: dict = {}
        if isinstance(evidence, dict):
            ev.update(evidence)
        elif evidence is not None:
            ev["summary"] = str(evidence)
        for k, v in extra.items():
            if v is not None:
                ev[k] = v
        f = Finding(
            module=self.module,
            type=type_,
            status=status if status in STATUSES else "finding",
            severity=severity,
            confidence=confidence,
            asset=str(asset),
            evidence=ev,
            source=source,
            remediation=remediation or REMEDIATIONS.get(type_, ""),
            collected_at=datetime.now(timezone.utc).isoformat(),
        )
        self.findings.append(f)
        return f

    def to_dict(self) -> dict:
        d = {
            "module": self.module,
            "status": self.status,
            "elapsed_seconds": round(self.elapsed, 2),
            "stats": self.stats,
            "findings": [f.to_dict() for f in self.findings],
        }
        if self.error:
            d["error"] = self.error
        return d


class ScanContext:
    """Shared state flowing through the module DAG."""

    def __init__(self, domain: str, out_dir, args):
        self.id = uuid.uuid4().hex[:12]
        self.domain = domain.lower().strip()
        self.out_dir = out_dir
        self.args = args
        self.data: dict[str, Any] = {}
        self.results: dict[str, ModuleResult] = {}
        self.findings: list[Finding] = []
        self.started = time.time()
        self.scope = None

    def key_list(self, key) -> set:
        s = self.data.setdefault(key, set())
        return s

    CONF_RANK = CONF_ORDER

    def merge_findings(self, result: ModuleResult):
        """Merge module findings dropping cross-module duplicates.

        On duplicate (type, asset, evidence-id) the higher-confidence record wins.
        """
        idx = {
            (f.type, f.asset, _ev_id(f)): i
            for i, f in enumerate(self.findings)
        }
        self.results[result.module] = result
        for f in result.findings:
            key = (f.type, f.asset, _ev_id(f))
            i = idx.get(key)
            if i is None:
                idx[key] = len(self.findings)
                self.findings.append(f)
            else:
                cur = self.findings[i]
                if CONF_ORDER.get(f.confidence, 1) > CONF_ORDER.get(cur.confidence, 1):
                    self.findings[i] = f

    def findings_by_severity(self) -> dict:
        out: dict[str, int] = {}
        for f in self.findings:
            out[f.severity] = out.get(f.severity, 0) + 1
        return out

    @property
    def elapsed(self) -> float:
        return time.time() - self.started


def _ev_id(f: Finding) -> str:
    for k in ("path", "url", "cve"):
        v = f.evidence.get(k)
        if v:
            return str(v)
    s = f.evidence.get("summary")
    return (str(s)[:120] if s else "")
