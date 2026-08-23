from __future__ import annotations

from .cloudhunt import CloudHuntModule
from .cvescan import CveScanModule
from .jsleak import JsLeakModule
from .leakhunt import LeakHuntModule
from .phishlab import PhishLabModule
from .recon import ReconModule

MODULES = {
    m.name: m for m in (
        ReconModule, CveScanModule, JsLeakModule, LeakHuntModule,
        CloudHuntModule, PhishLabModule,
    )
}

__all__ = ["MODULES", "ReconModule", "CveScanModule", "JsLeakModule",
           "LeakHuntModule", "CloudHuntModule", "PhishLabModule"]
