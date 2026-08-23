from __future__ import annotations

import asyncio
import ipaddress
import json
import random
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import urlparse

import aiohttp

from .config import RETRYABLE, random_ua
from .scope import ScopeBlocked

try:
    from aiohttp_socks import ProxyConnector
    HAS_SOCKS = True
except ImportError:
    ProxyConnector = None
    HAS_SOCKS = False

SOURCE_LIMITS = {
    "services.nvd.nist.gov": (5, 30),
    "api.github.com": (20, 60),
    "html.duckduckgo.com": (10, 30),
    "api.proxynova.com": (10, 60),
    "internetdb.shodan.io": (30, 60),
    "crt.sh": (10, 60),
    "api.securitytrails.com": (25, 60),
}


class RateLimiter:
    """Tiny min-interval limiter: global rps + per-host source policies."""

    def __init__(self, global_rps: Optional[float] = None):
        self.global_interval = 1.0 / global_rps if global_rps else 0.0
        self._next: dict[str, float] = {}
        self._lock = asyncio.Lock()

    def _interval_for(self, host: str) -> float:
        limit = SOURCE_LIMITS.get(host)
        if not limit:
            return self.global_interval
        max_req, per_sec = limit
        return max(self.global_interval, per_sec / max_req)

    async def acquire(self, host: str):
        interval = self._interval_for(host)
        if interval <= 0:
            return
        async with self._lock:
            now = time.monotonic()
            start = self._next.get("_global", 0)
            wait_until = max(now, start,
                             self._next.get(host, 0))
            self._next["_global"] = wait_until + self.global_interval
            self._next[host] = wait_until + interval
        sleep_for = wait_until - time.monotonic()
        if sleep_for > 0:
            await asyncio.sleep(sleep_for)


@dataclass
class HttpResponse:
    status: int
    body: str
    headers: dict
    cookies: list
    content_length: int

    @property
    def ok(self) -> bool:
        return self.status < 400


@dataclass
class HttpMetrics:
    requests: int = 0
    errors: int = 0
    timeouts: int = 0
    rate_limited: int = 0
    blocked: int = 0
    retries: int = 0
    latency_sum: float = 0.0
    by_host: dict = field(default_factory=lambda: defaultdict(
        lambda: {"requests": 0, "errors": 0, "rate_limited": 0}))

    def note(self, host: str, *, error: bool = False, timeout: bool = False,
             limited: bool = False, latency: float = 0.0):
        self.requests += 1
        self.latency_sum += latency
        h = self.by_host[host]
        h["requests"] += 1
        if error or timeout:
            self.errors += 1
            h["errors"] += 1
        if timeout:
            self.timeouts += 1
        if limited:
            self.rate_limited += 1
            h["rate_limited"] += 1


def parse_retry_after(value: Optional[str], cap: float = 15.0) -> Optional[float]:
    if not value:
        return None
    try:
        return min(float(int(value)), cap)
    except ValueError:
        pass
    try:
        from email.utils import parsedate_to_datetime
        dt = parsedate_to_datetime(value)
        delta = (dt.timestamp() if dt.tzinfo else dt.replace().timestamp()) \
            - time.time()
        return min(max(delta, 0.0), cap)
    except Exception:
        return None


def parse_json_loose(text: str) -> Any:
    try:
        return json.loads(text)
    except Exception:
        pass
    for ch in ("{", "["):
        try:
            start = text.index(ch)
            return json.loads(text[start:])
        except (ValueError, json.JSONDecodeError):
            continue
    return None


def _aiohttp_timeout(timeout: float):
    return aiohttp.ClientTimeout(total=timeout)


class HttpClient:
    """One shared aiohttp session with retry/backoff/rate-limits/metrics.

    scoped=True requests are validated against the target Scope (scheme,
    hostname in scope, private-IP resolution, redirect chain).
    """

    def __init__(self, cfg, *, connector_limit: int = 40,
                 total_timeout: Optional[float] = None,
                 scope=None, max_requests: Optional[int] = None,
                 rate_rps: Optional[float] = None):
        self.cfg = cfg
        self.scope = scope
        self.max_requests = max_requests
        self.limiter = RateLimiter(rate_rps)
        self.metrics = HttpMetrics()
        self.bytes_downloaded = 0
        self.requests_made = 0
        self._session: Optional[aiohttp.ClientSession] = None
        self._conn = aiohttp.TCPConnector(limit=connector_limit,
                                          ssl=cfg.tls_ssl)
        self._timeout = aiohttp.ClientTimeout(total=total_timeout)
        self._trust_env = bool(cfg.proxy)
        self._dns_cache: dict[str, list[str]] = {}
        self._request_lock = asyncio.Lock()

    async def __aenter__(self) -> "HttpClient":
        conn = self._conn
        proxy = self.cfg.proxy or ""
        if proxy.startswith(("socks4://", "socks5://", "socks5h://")):
            if not HAS_SOCKS:
                raise RuntimeError(
                    "proxy SOCKS requer: pip install aiohttp-socks")
            conn = ProxyConnector.from_url(proxy, ssl=self.cfg.tls_ssl)
            self._trust_env = False
        self._session = aiohttp.ClientSession(connector=conn,
                                              timeout=self._timeout,
                                              trust_env=self._trust_env)
        return self

    async def __aexit__(self, *exc):
        await self.close()

    async def close(self):
        if self._session and not self._session.closed:
            await self._session.close()

    @property
    def session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            raise RuntimeError("HttpClient session closed")
        return self._session

    def _headers(self, extra: Optional[dict] = None) -> dict:
        h = {
            "User-Agent": random_ua(),
            "Accept": "*/*",
            "Accept-Language": "en-US,en;q=0.8,pt-BR;q=0.7",
        }
        if extra:
            h.update(extra)
        return h

    async def _scoped_check(self, url: str):
        if self.scope is None:
            return
        ok, why = self.scope.url_allowed(url)
        if not ok:
            self.scope.note_blocked(url, why)
            self.metrics.blocked += 1
            raise ScopeBlocked(url, why)
        host = urlparse(url).hostname or ""
        try:
            ipaddress.ip_address(host)
        except ValueError:
            ips = await self._resolve_ips(host)
            if not ips:
                why = "dns_sem_resultado"
                self.scope.note_blocked(url, why)
                self.metrics.blocked += 1
                raise ScopeBlocked(url, why)
            for ip in ips:
                allowed, why = self.scope.ip_allowed(ip)
                if not allowed:
                    why = f"dns_{why}"
                    self.scope.note_blocked(url, why)
                    self.metrics.blocked += 1
                    raise ScopeBlocked(url, why)

    async def _reserve_request(self, host: str):
        async with self._request_lock:
            if self.max_requests and self.requests_made >= self.max_requests:
                raise RuntimeError(f"max_requests={self.max_requests} atingido")
            self.requests_made += 1
        await self.limiter.acquire(host)

    async def _resolve_ips(self, host: str) -> list[str]:
        ips = self._dns_cache.get(host)
        if ips is not None:
            return ips
        loop = asyncio.get_running_loop()
        try:
            infos = await asyncio.wait_for(loop.getaddrinfo(host, None), 6)
            ips = sorted({i[4][0] for i in infos})
        except Exception:
            ips = []
        self._dns_cache[host] = ips
        return ips

    async def request(
        self,
        method: str,
        url: str,
        *,
        params=None,
        headers=None,
        json_body=None,
        data=None,
        timeout: float = 30,
        retries: int = 2,
        allow_redirects: bool = True,
        max_body: int = 200_000,
        read: bool = True,
        proxy: bool = True,
        scoped: bool = False,
    ) -> HttpResponse:
        s = self.session
        cfg_proxy = str(self.cfg.proxy or "")
        px = self.cfg.proxy if (proxy and cfg_proxy
                                and not cfg_proxy.startswith("socks")) else None
        host = urlparse(url).hostname or ""
        last_err: Optional[Exception] = None
        backoff = 1.0
        retry_after: Optional[float] = None

        for attempt in range(retries + 1):
            t0 = time.monotonic()
            retry_after = None
            try:
                if scoped:
                    await self._scoped_check(url)
                kwargs = dict(
                    params=params, headers=self._headers(headers),
                    json=json_body, data=data,
                    timeout=_aiohttp_timeout(timeout),
                    allow_redirects=allow_redirects,
                )
                if px:
                    kwargs["proxy"] = px
                if scoped:
                    st, hdrs, cks, raw, _final = await self._scoped_send(
                        method, url, max_hops=5, max_body=max_body,
                        params=params, headers=headers, json_body=json_body,
                        data=data, timeout=timeout,
                        proxy_url=px,
                        allow_redirects=allow_redirects)
                else:
                    await self._reserve_request(host)
                    async with s.request(method, url, **kwargs) as resp:
                        st = resp.status
                        hdrs = resp.headers
                        cks = resp.cookies
                        raw = (await resp.content.read(max_body)) if read else b""
                lat = time.monotonic() - t0
                if not scoped:
                    self.metrics.note(host, error=st >= 400,
                                      limited=st == 429, latency=lat)
                if read:
                    self.bytes_downloaded += len(raw)
                body = raw.decode("utf-8", errors="replace") if read else ""
                body_len = len(body) if read else len(raw)
                result = HttpResponse(
                    status=st, body=body,
                    headers={k.lower(): v for k, v in dict(hdrs).items()},
                    cookies=[c.output(header="").strip() for c in cks.values()],
                    content_length=body_len)
                if st not in RETRYABLE or attempt >= retries:
                    return result
                retry_after = parse_retry_after(result.headers.get("retry-after"))
            except ScopeBlocked:
                raise
            except RuntimeError:
                raise
            except asyncio.TimeoutError as e:
                self.metrics.note(host, timeout=True)
                last_err = e
            except aiohttp.TooManyRedirects as e:
                self.metrics.note(host, error=True)
                last_err = e
                break
            except aiohttp.ClientResponseError as e:
                st = getattr(e, "status", None)
                self.metrics.note(host, limited=(st == 429), error=bool(st))
                ra_hdrs = getattr(e, "headers", None) or {}
                if st == 429:
                    retry_after = parse_retry_after(ra_hdrs.get("Retry-After"))
                last_err = e
                if isinstance(st, int) and st not in RETRYABLE:
                    break
            except Exception as e:
                self.metrics.note(host, error=True)
                last_err = e
            if attempt < retries:
                self.metrics.retries += 1
                sleep_for = retry_after if retry_after is not None \
                    else backoff + random.random() * 0.5
                backoff = min(backoff * 2, 15)
                await asyncio.sleep(min(sleep_for, 20))
        raise ConnectionError(f"{method} {url} failed: {last_err}")

    async def _scoped_send(self, method, url, *, max_hops, max_body,
                           params=None, headers=None, json_body=None,
                           data=None, timeout: float = 30,
                           proxy_url: Optional[str] = None,
                           allow_redirects: bool = True):
        """Redirect-following that validates every hop against the scope."""
        s = self.session
        current = url
        for _ in range(max_hops):
            await self._scoped_check(current)
            host = urlparse(current).hostname or ""
            await self._reserve_request(host)
            t0 = time.monotonic()
            request_kwargs = dict(
                params=params,
                headers=self._headers(headers),
                json=json_body,
                data=data,
                timeout=_aiohttp_timeout(timeout),
                allow_redirects=False,
            )
            if proxy_url:
                request_kwargs["proxy"] = proxy_url
            async with s.request(
                method, current, **request_kwargs,
            ) as resp:
                status = resp.status
                if resp.status in (301, 302, 303, 307, 308):
                    loc = resp.headers.get("Location")
                    if not allow_redirects or not loc:
                        raw = await resp.content.read(max_body)
                        self.metrics.note(host, error=status >= 400,
                                          limited=status == 429,
                                          latency=time.monotonic() - t0)
                        return status, resp.headers, resp.cookies, raw, current
                    from urllib.parse import urljoin
                    nxt = urljoin(current, loc)
                    await self._scoped_check(nxt)
                    self.metrics.note(host, error=status >= 400,
                                      limited=status == 429,
                                      latency=time.monotonic() - t0)
                    current = nxt
                    method = "GET" if resp.status in (301, 302, 303) else method
                    json_body = data = None
                    continue
                raw = await resp.content.read(max_body)
                self.metrics.note(host, error=status >= 400,
                                  limited=status == 429,
                                  latency=time.monotonic() - t0)
                return resp.status, resp.headers, resp.cookies, raw, current
        raise aiohttp.TooManyRedirects(f">{max_hops} hops em {url}")

    async def get(self, url: str, **kw) -> HttpResponse:
        return await self.request("GET", url, **kw)

    async def post(self, url: str, *, json_body=None, data=None,
                   **kw) -> HttpResponse:
        return await self.request("POST", url, json_body=json_body, data=data,
                                  **kw)

    async def get_json(self, url: str, *, timeout: float = 30, **kw) -> Any:
        r = await self.get(url, timeout=timeout, **kw)
        return parse_json_loose(r.body)

    async def probe_url(self, url: str, *, timeout: float = 10,
                        method: str = "GET", max_body: int = 200_000,
                        scoped: bool = False) -> HttpResponse:
        return await self.request(method, url, timeout=timeout,
                                  max_body=max_body, allow_redirects=True,
                                  scoped=scoped)
