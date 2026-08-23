from __future__ import annotations

import re

SECRET_VALUE_KEYS = {"value", "password", "secret", "token", "snippet",
                     "combolist"}

TOKEN_PATTERNS = [
    re.compile(r"(AKIA)[0-9A-Z]{16}"),
    re.compile(r"(AIza)[0-9A-Za-z\-_]{35}"),
    re.compile(r"(ghp_)[0-9a-zA-Z]{36}"),
    re.compile(r"(sk_live_)[0-9a-zA-Z]{24,}"),
    re.compile(r"(xox[abprs]-)[0-9a-zA-Z\-]{10,}"),
    re.compile(r"(SG\.)[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}"),
    re.compile(r"(eyJ[A-Za-z0-9_/+\-=]{20,}\.)[A-Za-z0-9_/+\-=.]+"),
]

PASSWORD_ASSIGN_RE = re.compile(
    r"((?i:password|passwd|pwd|secret|api[_-]?key|token)\s*[:=]\s*['\"]?)"
    r"([^'\"\s]{6,80})")


def mask_token(v: str) -> str:
    if len(v) <= 8:
        return "*" * len(v)
    keep = 4 if len(v) >= 20 else 2
    stars = max(4, min(16, len(v) - keep * 2))
    return f"{v[:keep]}{'*' * stars}{v[-keep:]}"


def scrub_text(s: str) -> str:
    out = s
    for pat in TOKEN_PATTERNS:
        out = pat.sub(lambda m: mask_token(m.group(0)), out)
    out = PASSWORD_ASSIGN_RE.sub(
        lambda m: f"{m.group(1)}{mask_token(m.group(2))}", out)
    return out


def mask_value(v: str) -> str:
    return mask_token(v)


def mask_record(obj, include_sensitive: bool = False):
    """Deep-copy with secrets masked unless explicitly included."""
    if include_sensitive:
        return obj
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if isinstance(v, str) and k in SECRET_VALUE_KEYS:
                out[k] = mask_value(v)
            else:
                out[k] = mask_record(v, include_sensitive)
        return out
    if isinstance(obj, list):
        return [mask_record(x, include_sensitive) for x in obj]
    if isinstance(obj, str):
        return scrub_text(obj)
    return obj
