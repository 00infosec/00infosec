from __future__ import annotations

import os
import random
from typing import Optional

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0",
]

RETRYABLE = {429, 502, 503, 504}


def api_key(cli_value: Optional[str], *env_names: str) -> Optional[str]:
    if cli_value:
        return cli_value
    for name in env_names:
        v = os.environ.get(name)
        if v:
            return v
    return None


class Config:
    def __init__(self, args):
        self.proxy: Optional[str] = getattr(args, "proxy", None)
        insecure = os.environ.get("INFOSEC_INSECURE_TLS", "").strip().lower() in {"1", "true", "yes"}
        self.tls_ssl = False if insecure else True
        self.verify_tls = not insecure
        self.nvd_key = api_key(getattr(args, "nvd_key", None), "NVD_API_KEY")
        self.gh_token = api_key(getattr(args, "gh_token", None), "GH_TOKEN", "GITHUB_TOKEN")
        self.vt_key = api_key(None, "VT_API_KEY")
        self.st_key = api_key(None, "ST_API_KEY")
        self.chaos_key = api_key(None, "CHAOS_API_KEY")
        self.shodan_key = api_key(None, "SHODAN_API_KEY")
        self.be_key = api_key(None, "BE_API_KEY")
        self.leakix_key = api_key(None, "LEAKIX_API_KEY")

    @property
    def has_proxy(self) -> bool:
        return bool(self.proxy)


def random_ua() -> str:
    return random.choice(USER_AGENTS)
