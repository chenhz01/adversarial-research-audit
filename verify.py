#!/usr/bin/env python3
"""Source authenticity verification: does a cited source actually exist,
and does its content match a recorded hash?

Upgrades the auditor from "arithmetic hygiene" to real verification:

    1. HEAD  — the URL resolves (status < 400)
    2. GET   — body fetched, SHA-256 computed (size-capped)
    3. HASH  — compare against a recorded hash; mismatch = content drift

Offline by default: if the network is unavailable the verifier returns
`ok=None / error=network-unavailable` and the audit marks itself `degraded`
rather than pretending the source is fine.

Zero dependencies (stdlib urllib). Usable as a library or as a CLI:

    python verify.py https://example.com/a https://example.com/b
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Dict, Iterable, List, Optional

DEFAULT_TIMEOUT = 10
DEFAULT_MAX_BYTES = 2 * 1024 * 1024  # 2 MB cap for hashing
USER_AGENT = "adversarial-research-audit/1.1 (+source authenticity check)"

# HTTP codes that mean "the transport failed", NOT "the source is dead":
# a corporate/sandbox proxy answering 502/503/504, or demanding auth (407).
PROXY_ERROR_CODES = {407, 502, 503, 504}


def _is_loopback(url: str) -> bool:
    try:
        host = urllib.parse.urlsplit(url).hostname or ""
    except ValueError:
        return False
    return host in ("localhost", "127.0.0.1", "::1", "0.0.0.0") or host.endswith(".localhost")


def _build_opener(
    url: str,
    proxy: str | None,
    redirect_handler: urllib.request.HTTPRedirectHandler | None = None,
) -> urllib.request.OpenerDirector:
    """Loopback must never go through an egress proxy — otherwise a sandbox or
    corporate proxy turns every localhost check into a 502 and we would report
    live sources as dead."""
    handlers: list[urllib.request.BaseHandler] = []
    if proxy:
        handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
    elif _is_loopback(url):
        handlers.append(urllib.request.ProxyHandler({}))
    else:
        no_proxy = (os.environ.get("NO_PROXY") or os.environ.get("no_proxy") or "")
        if no_proxy and any(h.strip() and h.strip() in url for h in no_proxy.split(",")):
            handlers.append(urllib.request.ProxyHandler({}))
    if redirect_handler is not None:
        handlers.append(redirect_handler)
    return urllib.request.build_opener(*handlers)


def _address_policy_error(url: str) -> str | None:
    """Return an error when a URL resolves outside the public Internet."""
    try:
        parsed = urllib.parse.urlsplit(url)
    except ValueError:
        return "invalid-url"
    if parsed.scheme.lower() not in {"http", "https"}:
        return "unsupported-scheme"
    host = parsed.hostname
    if not host:
        return "invalid-url"

    try:
        addresses = [ipaddress.ip_address(host)]
    except ValueError:
        try:
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            infos = socket.getaddrinfo(host, port,
                                       type=socket.SOCK_STREAM)
        except OSError as exc:
            raise urllib.error.URLError(f"dns-resolution-failed: {exc}") from exc
        addresses = []
        for info in infos:
            sockaddr = info[4]
            if sockaddr:
                addresses.append(ipaddress.ip_address(sockaddr[0]))

    if not addresses:
        raise urllib.error.URLError("dns-resolution-returned-no-addresses")
    if any(not address.is_global for address in addresses):
        return "blocked-private-address"
    return None


class _PolicyRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        error = _address_policy_error(newurl)
        if error:
            raise urllib.error.URLError(error)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class SourceVerifier:
    """Verify URLs exist and hash their content. Results are cached on disk so
    repeated audits don't re-hit the network."""

    def __init__(self, cache_path: Optional[str | Path] = None,
                 timeout: int = DEFAULT_TIMEOUT,
                 max_bytes: int = DEFAULT_MAX_BYTES,
                 offline: bool = False,
                 proxy: Optional[str] = None,
                 allow_private_networks: bool = True):
        self.timeout = timeout
        self.max_bytes = max_bytes
        self.offline = offline
        self.proxy = proxy
        self.allow_private_networks = allow_private_networks
        self.cache_path = Path(cache_path) if cache_path else None
        self.cache: Dict[str, dict] = {}
        if self.cache_path and self.cache_path.exists():
            try:
                self.cache = json.loads(self.cache_path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                self.cache = {}

    # ---- public API -------------------------------------------------------

    def verify(self, url: str, expect_sha256: Optional[str] = None,
               use_cache: bool = True) -> dict:
        """Return {url, ok, status_code, sha256, bytes, error, cached}."""
        if use_cache and url in self.cache:
            res = dict(self.cache[url])
            res["cached"] = True
            if expect_sha256:
                res["hash_match"] = (res.get("sha256") == expect_sha256)
            return res

        if self.offline:
            return {"url": url, "ok": None, "status_code": None, "sha256": None,
                    "bytes": None, "error": "offline-mode", "cached": False}

        res = self._fetch(url)
        if expect_sha256:
            res["hash_match"] = (res.get("sha256") == expect_sha256)
        if self.cache_path:
            self.cache[url] = {k: v for k, v in res.items() if k != "cached"}
            try:
                self.cache_path.write_text(
                    json.dumps(self.cache, ensure_ascii=False, indent=2), encoding="utf-8")
            except OSError:
                pass
        return res

    def verify_many(self, urls: Iterable[str]) -> List[dict]:
        return [self.verify(u) for u in urls]

    # ---- internals --------------------------------------------------------

    def _redirect_handler(self) -> urllib.request.HTTPRedirectHandler:
        if self.allow_private_networks:
            return urllib.request.HTTPRedirectHandler()
        return _PolicyRedirectHandler()

    def _request(self, req: urllib.request.Request, read_body: bool) -> tuple:
        opener = _build_opener(req.full_url, self.proxy, self._redirect_handler())
        with opener.open(req, timeout=self.timeout) as resp:
            body = resp.read(self.max_bytes) if read_body else b""
            return resp.status, dict(resp.headers), body

    def _fetch(self, url: str) -> dict:
        out = {"url": url, "ok": False, "status_code": None, "sha256": None,
               "bytes": None, "error": "", "cached": False,
               "via_proxy": bool(self.proxy) or (not _is_loopback(url)
                                                 and url.startswith(("http://", "https://"))
                                                 and urllib.request.getproxies())}
        if not url.lower().startswith(("http://", "https://")):
            out["error"] = "unsupported-scheme"
            return out
        if not self.allow_private_networks:
            try:
                policy_error = _address_policy_error(url)
            except urllib.error.URLError as exc:
                out["ok"] = None
                out["error"] = f"network-unavailable: {getattr(exc, 'reason', exc)}"
                return out
            if policy_error:
                out["ok"] = None
                out["error"] = policy_error
                return out
        head = urllib.request.Request(url, method="HEAD",
                                      headers={"User-Agent": USER_AGENT})
        try:
            status, headers, _ = self._request(head, read_body=False)
            out["status_code"] = status
            out["ok"] = status < 400
            if not out["ok"]:
                out["error"] = f"http-{status}"
                return out
        except urllib.error.HTTPError as e:
            out["status_code"] = e.code
            if e.code in PROXY_ERROR_CODES:
                # transport-layer failure, not proof of death
                out["ok"] = None
                out["error"] = (f"proxy-or-gateway-{e.code}: transport failed, "
                                f"cannot conclude the source is dead")
                return out
            if e.code in (403, 405, 501):     # HEAD not allowed → fall back to GET
                pass
            else:
                out["error"] = f"http-{e.code}"
                return out
        except urllib.error.URLError as e:
            # network failure ≠ dead source. Honest semantics: unknown.
            out["ok"] = None
            reason = str(getattr(e, "reason", e))
            out["error"] = reason if reason == "blocked-private-address" else f"network-unavailable: {reason}"
            return out
        except Exception as e:  # timeout, ssl, redirect loops …
            out["ok"] = None
            out["error"] = f"unknown: {type(e).__name__}: {e}"
            return out

        # body fetch → content hash
        get = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        try:
            status, headers, body = self._request(get, read_body=True)
            out["status_code"] = status
            out["ok"] = status < 400
            out["bytes"] = len(body)
            out["sha256"] = hashlib.sha256(body).hexdigest()
        except urllib.error.HTTPError as e:
            out["status_code"] = e.code
            if e.code in PROXY_ERROR_CODES:
                out["ok"] = None
            else:
                out["ok"] = False
            out["error"] = f"body-fetch-failed: HTTPError: {e}"
        except Exception as e:
            # HEAD alone proves existence, not that the source could be verified.
            out["ok"] = None
            out["error"] = f"body-fetch-failed: {type(e).__name__}: {e}"
        return out
    def summary(self, results: List[dict]) -> dict:
        total = len(results)
        alive = sum(1 for r in results if r.get("ok") is True)
        dead = sum(1 for r in results if r.get("ok") is False)
        unknown = total - alive - dead
        drifted = sum(1 for r in results if r.get("hash_match") is False)
        return {"total": total, "alive": alive, "dead": dead,
                "unknown": unknown, "hash_drift": drifted,
                "degraded": unknown > 0}


def main(argv: List[str]) -> int:
    urls = [a for a in argv if not a.startswith("--")]
    if not urls:
        print(__doc__)
        return 2
    cache = None
    if "--cache" in argv:
        i = argv.index("--cache")
        cache = argv[i + 1] if i + 1 < len(argv) else None
    offline = "--offline" in argv
    v = SourceVerifier(cache_path=cache, offline=offline)
    results = v.verify_many(urls)
    for r in results:
        mark = "ALIVE" if r["ok"] else ("UNKNOWN" if r["ok"] is None else "DEAD")
        print(f"[{mark}] {r['url']}  status={r['status_code']} "
              f"sha256={(r['sha256'] or '-')[:12]} {r['error']}")
    s = v.summary(results)
    print(f"summary: {s['alive']}/{s['total']} alive, {s['dead']} dead, "
          f"{s['unknown']} unknown, hash_drift={s['hash_drift']}")
    return 0 if s["dead"] == 0 and not s["degraded"] else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
