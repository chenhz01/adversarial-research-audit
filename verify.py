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

Transport safety (DNS-rebinding hardened): every hostname is resolved once,
validated against the transport policy (restricted by default — only global
public addresses are connectable), and the socket dials the validated address
directly. SNI/TLS verification and the Host header keep using the original
hostname. The pin is shared by HEAD, GET and same-host redirect hops, and
every cross-host redirect hop is re-resolved and re-validated. Callers that
legitimately need loopback/private targets must pass
`allow_private_networks=True` explicitly — the restricted default never
inherits silently.

Proxy policy (restricted mode fails closed): a configured proxy — an explicit
`proxy=` argument or any environment proxy that applies to the URL — takes DNS
away from this module, because the proxy performs the lookup. Address
validation and pinning therefore cannot run, so restricted mode **rejects**
that configuration with `proxy-policy-unsupported` instead of silently falling
back to an unpinned opener. Callers that accept the weaker guarantee through a
proxy must opt in with `allow_private_networks=True`. Loopback and
NO_PROXY-matched URLs never traverse an egress proxy and keep the pinned path.

Four outcomes, not two: every result carries `outcome` ∈
`alive | dead | unknown | blocked`. `alive`/`dead` are liveness claims;
`unknown` (transport failure, timeout, proxy rejection) is the honest refusal
to claim either; `blocked` is a policy decision not to access the source,
which establishes nothing about liveness. Only `dead` is counted as dead, and
failing a run on a policy block is an explicit opt-in
(`fail_on_policy_block=True`), never an emergent artefact.

Zero dependencies (stdlib urllib). Usable as a library or as a CLI:

    python verify.py https://example.com/a https://example.com/b
"""
from __future__ import annotations

import errno
import functools
import hashlib
import http.client
import ipaddress
import json
import os
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

DEFAULT_TIMEOUT = 10
DEFAULT_MAX_BYTES = 2 * 1024 * 1024  # 2 MB cap for hashing
USER_AGENT = "adversarial-research-audit/1.1 (+source authenticity check)"

# HTTP codes that mean "the transport failed", NOT "the source is dead":
# a corporate/sandbox proxy answering 502/503/504, or demanding auth (407).
PROXY_ERROR_CODES = {407, 502, 503, 504}


@dataclass
class TransportPolicy:
    """Connection-safety policy for outbound source verification.

    allow_private_networks=False (restricted, fail-closed) rejects any URL whose
    DNS records resolve exclusively to non-public addresses (loopback, RFC1918,
    link-local, CGNAT, documentation, multicast, reserved, IPv4-mapped IPv6).
    The restricted default is deliberate: callers that legitimately need
    loopback/private targets must pass allow_private_networks=True explicitly,
    never inherit it silently.
    """

    allow_private_networks: bool = False
    pin_ttl: float = 30.0  # seconds a validated (host, port) -> IP pin stays fresh
    fail_on_policy_block: bool = False  # explicit opt-in: a policy denial fails the run


class _PolicyBlocked(urllib.error.URLError):
    """Raised when DNS records fail the transport policy (definite policy fact,
    but NOT evidence about liveness — see `outcome == "blocked"`)."""


class _ProxyPolicyUnsupported(urllib.error.URLError):
    """Raised in restricted mode when a proxy is configured.

    Through a proxy we do not perform the DNS lookup, so address validation and
    pinning cannot run; restricted mode refuses that configuration rather than
    silently degrading the boundary. Not a liveness signal (`outcome` stays
    `unknown`).
    """


def _addr_allowed(ip: ipaddress.IPAddress, allow_private_networks: bool) -> bool:
    # Unwrap IPv4-mapped IPv6 (::ffff:10.0.0.1 must be judged as 10.0.0.1)
    if ip.version == 6 and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if ip.is_multicast or ip.is_reserved or ip.is_unspecified:
        # CPython 3.13+ marks some multicast/reserved ranges is_global=True;
        # deny them explicitly so the docstring contract holds.
        return allow_private_networks
    return bool(ip.is_global) or allow_private_networks


def _resolve_pinned(hostname: str, port: int,
                    allow_private_networks: bool) -> str:
    """Resolve hostname once and return ONE validated public IP to connect to.

    The caller connects to the returned address directly (SNI/Host still carry
    the original hostname), so a DNS rebinding flip between validation and
    connection cannot redirect the socket. Mixed records: non-public entries
    are dropped, never connected to.
    """
    try:
        infos = socket.getaddrinfo(hostname, port, 0, socket.SOCK_STREAM)
    except socket.gaierror as e:
        raise urllib.error.URLError(f"dns-resolution-failed: {e}") from e
    seen: List[ipaddress.IPAddress] = []
    for info in infos:
        try:
            addr = ipaddress.ip_address(info[4][0])
        except ValueError:
            continue
        if addr not in seen:
            seen.append(addr)
    if not seen:
        raise urllib.error.URLError(f"dns-resolution-empty: {hostname}")
    allowed = [a for a in seen if _addr_allowed(a, allow_private_networks)]
    if not allowed:
        raise _PolicyBlocked(
            "policy-blocked: " + hostname + " resolves only to non-public "
            "address(es) (" + ", ".join(str(a) for a in seen) + ")")
    return str(allowed[0])


class _PinnedHTTPConnection(http.client.HTTPConnection):
    """HTTPConnection that dials the validated IP, never a fresh DNS lookup."""

    def __init__(self, *args, validated_ip: Optional[str] = None, **kwargs):
        super().__init__(*args, **kwargs)
        self._validated_ip = validated_ip

    def connect(self):
        target = self._validated_ip or self.host
        sys.audit("http.client.connect", self, target, self.port)
        self.sock = socket.create_connection(
            (target, self.port), self.timeout, self.source_address)
        try:
            self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError as e:
            if e.errno != errno.ENOPROTOOPT:
                raise


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPSConnection that dials the validated IP; SNI/cert-check keep using
    the original hostname so TLS verification semantics are unchanged."""

    def __init__(self, *args, validated_ip: Optional[str] = None, **kwargs):
        super().__init__(*args, **kwargs)
        self._validated_ip = validated_ip

    def connect(self):
        target = self._validated_ip or self.host
        sys.audit("http.client.connect", self, target, self.port)
        self.sock = socket.create_connection(
            (target, self.port), self.timeout, self.source_address)
        try:
            self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError as e:
            if e.errno != errno.ENOPROTOOPT:
                raise
        server_hostname = self.host  # original hostname, not the pinned IP
        self.sock = self._context.wrap_socket(
            self.sock, server_hostname=server_hostname)


class _PinnedHTTPHandler(urllib.request.HTTPHandler):
    def __init__(self, pin_fn, context=None):
        super().__init__()
        self._pin_fn = pin_fn

    def http_open(self, req):
        ip = self._pin_fn(req, "http")
        conn = functools.partial(_PinnedHTTPConnection, validated_ip=ip)
        return self.do_open(conn, req)


class _PinnedHTTPSHandler(urllib.request.HTTPSHandler):
    def __init__(self, pin_fn, context=None):
        super().__init__(context=context)
        self._pin_fn = pin_fn

    def https_open(self, req):
        ip = self._pin_fn(req, "https")
        conn = functools.partial(_PinnedHTTPSConnection, validated_ip=ip)
        return self.do_open(conn, req, context=self._context)


def _is_loopback(url: str) -> bool:
    try:
        host = urllib.parse.urlsplit(url).hostname or ""
    except ValueError:
        return False
    return host in ("localhost", "127.0.0.1", "::1", "0.0.0.0") or host.endswith(".localhost")


def _no_proxy_match(url: str) -> bool:
    """True when NO_PROXY/no_proxy names a host that appears in the URL.

    Such URLs never traverse an egress proxy, so they keep the pinned path.
    """
    no_proxy = (os.environ.get("NO_PROXY") or os.environ.get("no_proxy") or "")
    return bool(no_proxy) and any(
        h.strip() and h.strip() in url for h in no_proxy.split(","))


def _build_opener(url: str, proxy: str | None,
                  http_handler, https_handler,
                  allow_private_networks: bool = False
                  ) -> urllib.request.OpenerDirector:
    """Build the opener for one request.

    Direct (proxy-free) connections go through the pinned handlers: DNS is
    resolved+validated once, and the socket dials the validated address only.

    Loopback and NO_PROXY-matched URLs never traverse an egress proxy, so they
    keep the pinned handlers unconditionally.

    A configured proxy (explicit `proxy`, or any environment proxy that applies
    to the URL) performs the DNS lookup itself, so validation and pinning cannot
    run. Restricted mode must not silently drop that boundary: it rejects the
    configuration with `_ProxyPolicyUnsupported` (fail closed). Callers that
    accept the weaker guarantee through a proxy must opt in explicitly with
    `allow_private_networks=True`.
    """
    if _is_loopback(url) or _no_proxy_match(url):
        return urllib.request.build_opener(
            urllib.request.ProxyHandler({}), http_handler, https_handler)
    env_proxies = urllib.request.getproxies()
    if proxy or env_proxies:
        if not allow_private_networks:
            raise _ProxyPolicyUnsupported(
                "proxy-policy-unsupported: a proxy is configured (explicit=%r, "
                "environment=%r), so DNS resolves at the proxy and address "
                "validation/pinning cannot run; restricted mode refuses rather "
                "than silently degrading the boundary. Clear the proxy, or opt "
                "in explicitly with allow_private_networks=True."
                % (proxy, sorted(env_proxies) if not proxy else []))
        if proxy:
            return urllib.request.build_opener(
                urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
        return urllib.request.build_opener()
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({}), http_handler, https_handler)


def _proxy_rejection_text(exc: BaseException) -> str:
    """Normalise a proxy-policy rejection into a stable, greppable error text."""
    text = str(getattr(exc, "reason", exc)) or exc.__class__.__name__
    if not text.startswith("proxy-policy-unsupported"):
        text = f"proxy-policy-unsupported: {text}"
    return text


def _outcome_of(res: dict) -> str:
    """Project a result onto the four-state outcome (alive|dead|unknown|blocked).

    `outcome` is authoritative when a fetch set it; otherwise it is derived
    from the liveness projection `ok`, so cache entries written by an older
    version stay readable.
    """
    outcome = res.get("outcome")
    if outcome in ("alive", "dead", "unknown", "blocked"):
        return outcome
    if res.get("ok") is True:
        return "alive"
    if res.get("ok") is False:
        return "dead"
    return "unknown"


class SourceVerifier:
    """Verify URLs exist and hash their content. Results are cached on disk so
    repeated audits don't re-hit the network."""

    def __init__(self, cache_path: Optional[str | Path] = None,
                 timeout: int = DEFAULT_TIMEOUT,
                 max_bytes: int = DEFAULT_MAX_BYTES,
                 offline: bool = False,
                 proxy: Optional[str] = None,
                 allow_private_networks: bool = False,
                 pin_ttl: float = 30.0,
                 fail_on_policy_block: bool = False):
        self.timeout = timeout
        self.max_bytes = max_bytes
        self.offline = offline
        self.proxy = proxy
        self.policy = TransportPolicy(allow_private_networks=allow_private_networks,
                                      pin_ttl=pin_ttl,
                                      fail_on_policy_block=fail_on_policy_block)
        # Validated-address pins: (scheme, host, port) -> (ip, monotonic ts).
        # Shared by HEAD and GET (and same-host redirect hops) so a DNS flip
        # between requests cannot re-point the socket inside one verify() call.
        self._pins: Dict[Tuple[str, str, int], Tuple[str, float]] = {}
        self._http_handler = _PinnedHTTPHandler(self._pin_for_request)
        self._https_handler = _PinnedHTTPSHandler(self._pin_for_request)
        self.cache_path = Path(cache_path) if cache_path else None
        self.cache: Dict[str, dict] = {}
        if self.cache_path and self.cache_path.exists():
            try:
                self.cache = json.loads(self.cache_path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                self.cache = {}

    # ---- transport policy --------------------------------------------------

    def _pin_for_request(self, req: urllib.request.Request, scheme: str) -> str:
        """Return the validated IP for this request, from cache when fresh."""
        try:
            u = urllib.parse.urlsplit(req.full_url)
        except ValueError as e:
            raise urllib.error.URLError(f"invalid-url: {e}") from e
        hostname = u.hostname
        if not hostname:
            raise urllib.error.URLError("no host given")
        port = u.port or (443 if scheme == "https" else 80)
        key = (scheme, hostname, port)
        now = time.monotonic()
        cached = self._pins.get(key)
        if cached and (now - cached[1]) < self.policy.pin_ttl:
            return cached[0]
        ip = _resolve_pinned(hostname, port, self.policy.allow_private_networks)
        if len(self._pins) > 256:
            self._pins.clear()
        self._pins[key] = (ip, now)
        return ip

    # ---- public API -------------------------------------------------------

    def verify(self, url: str, expect_sha256: Optional[str] = None,
               use_cache: bool = True) -> dict:
        """Return {url, ok, outcome, status_code, sha256, bytes, error, cached}.

        `outcome` is the authoritative four-state field (alive | dead | unknown
        | blocked); `ok` is its liveness projection (True / False / None, where
        None covers both unknown and blocked).
        """
        if use_cache and url in self.cache:
            res = dict(self.cache[url])
            res["outcome"] = _outcome_of(res)
            res["cached"] = True
            if expect_sha256:
                res["hash_match"] = (res.get("sha256") == expect_sha256)
            return res

        if self.offline:
            return {"url": url, "ok": None, "outcome": "unknown",
                    "status_code": None, "sha256": None,
                    "bytes": None, "error": "offline-mode", "cached": False}

        res = self._fetch(url)
        res["outcome"] = _outcome_of(res)
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

    def _request(self, req: urllib.request.Request, read_body: bool) -> tuple:
        opener = _build_opener(req.full_url, self.proxy,
                               self._http_handler, self._https_handler,
                               allow_private_networks=(
                                   self.policy.allow_private_networks))
        with opener.open(req, timeout=self.timeout) as resp:
            body = resp.read(self.max_bytes) if read_body else b""
            return resp.status, dict(resp.headers), body

    def _fetch(self, url: str) -> dict:
        out = {"url": url, "ok": False, "outcome": "dead", "status_code": None,
               "sha256": None, "bytes": None, "error": "", "cached": False,
               "via_proxy": bool(self.proxy) or (not _is_loopback(url)
                                                 and url.startswith(("http://", "https://"))
                                                 and urllib.request.getproxies())}
        if not url.lower().startswith(("http://", "https://")):
            # Not a source-liveness question at all: the input is not a URL we
            # can verify. Kept as a definite rejection (dead), never counted as
            # a network unknown.
            out["error"] = "unsupported-scheme"
            return out
        head = urllib.request.Request(url, method="HEAD",
                                      headers={"User-Agent": USER_AGENT})
        try:
            status, headers, _ = self._request(head, read_body=False)
            out["status_code"] = status
            out["ok"] = status < 400
            out["outcome"] = "alive" if out["ok"] else "dead"
            if not out["ok"]:
                out["error"] = f"http-{status}"
                return out
        except _ProxyPolicyUnsupported as e:
            # Restricted mode refuses a proxy configuration rather than
            # skipping address validation. No liveness claim: unknown.
            out["ok"] = None
            out["outcome"] = "unknown"
            out["error"] = _proxy_rejection_text(e)
            return out
        except _PolicyBlocked as e:
            # A policy decision NOT to access the source. This is definite, but
            # it establishes nothing about liveness — never counted as dead.
            out["ok"] = None
            out["outcome"] = "blocked"
            out["error"] = str(e.reason)
            return out
        except urllib.error.HTTPError as e:
            out["status_code"] = e.code
            if e.code in PROXY_ERROR_CODES:
                # transport-layer failure, not proof of death
                out["ok"] = None
                out["outcome"] = "unknown"
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
            out["outcome"] = "unknown"
            out["error"] = f"network-unavailable: {getattr(e, 'reason', e)}"
            return out
        except Exception as e:  # timeout, ssl, redirect loops …
            out["ok"] = None
            out["outcome"] = "unknown"
            out["error"] = f"unknown: {type(e).__name__}: {e}"
            return out

        # body fetch → content hash
        get = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        try:
            status, headers, body = self._request(get, read_body=True)
            out["status_code"] = status
            out["ok"] = status < 400
            out["outcome"] = "alive" if out["ok"] else "dead"
            out["bytes"] = len(body)
            out["sha256"] = hashlib.sha256(body).hexdigest()
        except _ProxyPolicyUnsupported as e:
            out["ok"] = None
            out["outcome"] = "unknown"
            out["error"] = _proxy_rejection_text(e)
        except _PolicyBlocked as e:
            # redirect hop resolved to a non-public address: a policy decision,
            # not evidence that the source is dead
            out["ok"] = None
            out["outcome"] = "blocked"
            out["error"] = str(e.reason)
        except urllib.error.URLError as e:
            # transport failed mid-fetch (e.g. refused at a redirect hop):
            # that is uncertainty, not proof of death — honest ok=None
            out["ok"] = None
            out["outcome"] = "unknown"
            out["error"] = f"body-fetch-network-unavailable: {getattr(e, 'reason', e)}"
        except Exception as e:
            # HEAD said it exists but the body failed (TimeoutError, SSL, …):
            # the content is unverifiable, so this is NOT a successful
            # verification — degrade to unknown instead of inheriting the
            # HEAD stage's ok=True.
            out["ok"] = None
            out["outcome"] = "unknown"
            out["error"] = f"body-fetch-failed: {type(e).__name__}: {e}"
        return out

    def summary(self, results: List[dict]) -> dict:
        """Aggregate results.

        `dead` counts only definite death (`outcome == "dead"`); policy-blocked
        sources are reported separately and never inflate `dead`, because a
        decision not to access a source says nothing about its liveness. Any
        unknown or blocked result makes the run `degraded` (the verification is
        partial). Failing the run on a policy block is the explicit opt-in
        `fail_on_policy_block`, surfaced as `policy_failure`.
        """
        total = len(results)
        outcomes = [_outcome_of(r) for r in results]
        alive = outcomes.count("alive")
        dead = outcomes.count("dead")
        blocked = outcomes.count("blocked")
        unknown = total - alive - dead - blocked
        drifted = sum(1 for r in results if r.get("hash_match") is False)
        summary = {"total": total, "alive": alive, "dead": dead,
                   "unknown": unknown, "blocked": blocked,
                   "hash_drift": drifted,
                   "degraded": unknown > 0 or blocked > 0}
        if self.policy.fail_on_policy_block and blocked:
            summary["policy_failure"] = True
        return summary


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
    v = SourceVerifier(cache_path=cache, offline=offline,
                       fail_on_policy_block="--fail-on-policy-block" in argv)
    results = v.verify_many(urls)
    marks = {"alive": "ALIVE", "dead": "DEAD",
             "unknown": "UNKNOWN", "blocked": "BLOCKED"}
    for r in results:
        print(f"[{marks[_outcome_of(r)]}] {r['url']}  status={r['status_code']} "
              f"sha256={(r['sha256'] or '-')[:12]} {r['error']}")
    s = v.summary(results)
    print(f"summary: {s['alive']}/{s['total']} alive, {s['dead']} dead, "
          f"{s['blocked']} policy-blocked, {s['unknown']} unknown, "
          f"hash_drift={s['hash_drift']}")
    failed = s["dead"] > 0 or s["degraded"] or s.get("policy_failure", False)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
