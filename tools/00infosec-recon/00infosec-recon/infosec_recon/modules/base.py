from __future__ import annotations

from abc import ABC, abstractmethod

from ..core.models import ModuleResult


class Module(ABC):
    """Contract every recon/vuln module implements.

    name     : unique id used in CLI (--only/--skip), results and findings
    provides : keys written into ctx.data
    requires : ctx.data keys this module needs from other modules
    """

    name: str = "base"
    description: str = ""
    provides: tuple = ()
    requires: tuple = ()

    def __init__(self, ctx, http, dns, cfg, console):
        self.ctx = ctx
        self.http = http
        self.dns = dns
        self.cfg = cfg
        self.console = console
        self.result = ModuleResult(self.name)

    @abstractmethod
    async def run(self): ...

    def add(self, *a, **kw):
        return self.result.add(*a, **kw)
