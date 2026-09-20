"""Tests for source authenticity verification (verify.py).
Uses a local HTTP server so no external network is required."""
from __future__ import annotations

import functools
import hashlib
import http.server
import os
import socket
import socketserver
import sys
import tempfile
import threading
import unittest
import urllib.request
from contextlib import contextmanager
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from verify import SourceVerifier  # noqa: E402


class _Handler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *a):  # silence
        pass


class LocalServer:
    def __init__(self, directory: str):
        handler = functools.partial(_Handler, directory=directory)
        self.httpd = socketserver.TCPServer(("127.0.0.1", 0), handler)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def url(self, path: str) -> str:
        return f"http://127.0.0.1:{self.port}/{path}"

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


class TestSourceVerifier(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        p = Path(cls.tmp.name)
        (p / "exists.txt").write_text("hello authenticity", encoding="utf-8")
        cls.expected_sha = hashlib.sha256(b"hello authenticity").hexdigest()
        cls.srv = LocalServer(cls.tmp.name)

    @classmethod
    def tearDownClass(cls):
        cls.srv.close()
        cls.tmp.cleanup()

    def test_alive_with_content_hash(self):
        v = SourceVerifier(allow_private_networks=True)
        r = v.verify(self.srv.url("exists.txt"))
        self.assertTrue(r["ok"])
        self.assertEqual(r["status_code"], 200)
        self.assertEqual(r["sha256"], self.expected_sha)
        self.assertEqual(r["bytes"], len(b"hello authenticity"))

    def test_hash_match_flag(self):
        v = SourceVerifier(allow_private_networks=True)
        good = v.verify(self.srv.url("exists.txt"), expect_sha256=self.expected_sha)
        self.assertTrue(good["hash_match"])
        bad = v.verify(self.srv.url("exists.txt"), expect_sha256="0" * 64)
        self.assertFalse(bad["hash_match"])

    def test_dead_url(self):
        v = SourceVerifier(allow_private_networks=True)
        r = v.verify(self.srv.url("missing.txt"))
        self.assertFalse(r["ok"])
        self.assertEqual(r["status_code"], 404)

    def test_offline_mode_is_unknown_not_ok(self):
        v = SourceVerifier(offline=True)
        r = v.verify(self.srv.url("exists.txt"))
        self.assertIsNone(r["ok"])
        self.assertEqual(r["error"], "offline-mode")

    def test_cache_prevents_refetch(self):
        with tempfile.TemporaryDirectory() as td:
            cache = Path(td) / "c.json"
            v1 = SourceVerifier(cache_path=cache)
            v1.verify(self.srv.url("exists.txt"))
            v2 = SourceVerifier(cache_path=cache)
            r = v2.verify(self.srv.url("exists.txt"))
            self.assertTrue(r["cached"])

    def test_summary_marks_degraded_on_unknown(self):
        v = SourceVerifier(allow_private_networks=True)
        results = [v.verify(self.srv.url("exists.txt")),
                   v.verify(self.srv.url("gone.txt"))]
        s = v.summary(results)
        self.assertEqual((s["total"], s["alive"], s["dead"]), (2, 1, 1))
        self.assertFalse(s["degraded"])
        s2 = v.summary([SourceVerifier(offline=True).verify("http://x/y")])
        self.assertTrue(s2["degraded"])

    def test_bad_scheme_rejected(self):
        r = SourceVerifier(allow_private_networks=True).verify("raw/sources/local.md")
        self.assertFalse(r["ok"])
        self.assertEqual(r["error"], "unsupported-scheme")


class _GatewayErrorHandler(http.server.BaseHTTPRequestHandler):
    """Simulates an egress proxy / gateway failing the transport."""

    def _fail(self):
        self.send_response(503)
        self.end_headers()
        self.wfile.write(b"gateway error")

    do_HEAD = _fail
    do_GET = _fail

    def log_message(self, *a):
        pass


class GatewayServer:
    def __init__(self):
        self.httpd = socketserver.TCPServer(("127.0.0.1", 0), _GatewayErrorHandler)
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


class TestProxyHonesty(unittest.TestCase):
    def test_gateway_error_is_unknown_not_dead(self):
        srv = GatewayServer()
        try:
            r = SourceVerifier(allow_private_networks=True).verify(f"http://127.0.0.1:{srv.port}/anything")
            self.assertIsNone(r["ok"], "transport failure must not mean 'dead source'")
            self.assertIn("proxy-or-gateway-503", r["error"])
        finally:
            srv.close()

    def test_loopback_bypasses_egress_proxy(self):
        import os
        os.environ["HTTP_PROXY"] = "http://127.0.0.1:1"     # a dead proxy
        try:
            with tempfile.TemporaryDirectory() as td:
                Path(td, "f.txt").write_text("ok", encoding="utf-8")
                srv = LocalServer(td)
                try:
                    r = SourceVerifier(allow_private_networks=True).verify(srv.url("f.txt"))
                    self.assertTrue(r["ok"], "loopback must bypass HTTP_PROXY")
                    self.assertFalse(r["via_proxy"])
                finally:
                    srv.close()
        finally:
            os.environ.pop("HTTP_PROXY", None)


class TestTransportPolicy(unittest.TestCase):
    """DNS-rebinding hardening: resolve once, validate, dial the validated IP."""

    PUBLIC_IP = "93.184.216.34"  # example.com's long-standing public address

    @contextmanager
    def _direct_network(self):
        """Remove proxy env vars and neutralize registry proxies so the direct
        (pinned) transport path runs — on hosts with a global HTTP_PROXY or a
        system proxy the verifier delegates DNS to the proxy by design and
        pinning is skipped."""
        keys = ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy",
                "ALL_PROXY", "all_proxy"]
        saved = {k: os.environ.pop(k) for k in keys if k in os.environ}
        try:
            with mock.patch.object(urllib.request, "getproxies", return_value={}):
                yield
        finally:
            os.environ.update(saved)

    @staticmethod
    def _fake_resolver(route):
        """Build a getaddrinfo replacement. route: hostname -> ip, or a list
        of per-call ips consumed in order (for flip simulations). Falls back
        to the REAL resolver captured at creation time (never re-enters the
        patched symbol)."""
        counters: dict = {}
        real = socket.getaddrinfo

        def fake(host, port=None, *a, **k):
            spec = route.get(host)
            if spec is None:
                return real(host, port, *a, **k)
            if isinstance(spec, list):
                i = counters.get(host, 0)
                counters[host] = i + 1
                ip = spec[min(i, len(spec) - 1)]
            else:
                ip = spec
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port or 80))]

        return fake

    def _recorder(self, allow_real_for=("127.0.0.1",)):
        """create_connection replacement: records every dial target, refuses
        non-loopback dials (no real egress in tests)."""
        calls = []
        real = socket.create_connection

        def fake(address, timeout=None, source_address=None):
            calls.append((address[0], address[1]))
            if address[0] in allow_real_for:
                return real(address, timeout=timeout, source_address=source_address)
            raise ConnectionRefusedError("recorded; refused (test guard)")

        return fake, calls

    def test_loopback_blocked_by_restricted_default(self):
        with self._direct_network():
            r = SourceVerifier().verify("http://127.0.0.1:9/x")
        # A policy denial is definite, but it establishes nothing about
        # liveness: blocked is its own outcome, never "dead".
        self.assertIsNone(r["ok"])
        self.assertEqual(r["outcome"], "blocked")
        self.assertTrue(r["error"].startswith("policy-blocked"),
                        f"expected policy-blocked, got {r['error']!r}")

    def test_private_resolving_hostname_blocked(self):
        fake = self._fake_resolver({"private.example.com": "10.0.0.5"})
        with self._direct_network(), mock.patch.object(socket, "getaddrinfo", fake):
            r = SourceVerifier().verify("http://private.example.com/x")
        self.assertIsNone(r["ok"])
        self.assertEqual(r["outcome"], "blocked")
        self.assertIn("policy-blocked", r["error"])
        self.assertIn("10.0.0.5", r["error"])

    def test_rebinding_flip_never_dials_private_ip(self):
        # DNS answers public first (validation), then flips to loopback
        # (the rebinding attack). The socket must only ever dial the IP that
        # was validated.
        fake_resolve = self._fake_resolver(
            {"rebind.example.com": [self.PUBLIC_IP, "127.0.0.1"]})
        dial, calls = self._recorder(allow_real_for=())
        with self._direct_network(), \
             mock.patch.object(socket, "getaddrinfo", fake_resolve), \
             mock.patch.object(socket, "create_connection", dial):
            v = SourceVerifier()  # restricted default
            r = v.verify("http://rebind.example.com/x")
        dialed = {ip for ip, _ in calls}
        self.assertEqual(dialed, {self.PUBLIC_IP},
                         f"rebinding reached the socket: dialed {dialed}")
        self.assertIsNone(r["ok"])  # refused dial = network-unavailable, not dead

    def test_redirect_hop_is_revalidated(self):
        # Hop 1: local server (loopback, explicit allow) 302s to a public
        # hostname. Hop 2 must be resolved+validated+dialed on the policy path.
        class _Redirect(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(302)
                self.send_header(
                    "Location",
                    f"http://public.example.com:{self.server.server_address[1]}/x")
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *a):
                pass

        httpd = socketserver.TCPServer(("127.0.0.1", 0), _Redirect)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        fake_resolve = self._fake_resolver({"public.example.com": self.PUBLIC_IP})
        dial, calls = self._recorder(allow_real_for=("127.0.0.1",))
        try:
            with self._direct_network(), \
                 mock.patch.object(socket, "getaddrinfo", fake_resolve), \
                 mock.patch.object(socket, "create_connection", dial):
                v = SourceVerifier(allow_private_networks=True)
                r = v.verify(f"http://127.0.0.1:{httpd.server_address[1]}/redirect")
            dialed = [ip for ip, _ in calls]
            self.assertIn("127.0.0.1", dialed, "hop 1 should reach the local server")
            self.assertIn(self.PUBLIC_IP, dialed,
                          "hop 2 must be dialed at the validated address")
        finally:
            httpd.shutdown()
            httpd.server_close()
        # hop 2 was refused by the test guard: honest unknown, not 'dead'
        self.assertIsNone(r["ok"])

    def test_ipv4_mapped_ipv6_blocked(self):
        # ::ffff:10.0.0.1 must be judged as 10.0.0.1 (private), not as global IPv6
        fake = self._fake_resolver({"mapped.example.com": "::ffff:10.0.0.1"})
        with self._direct_network(), mock.patch.object(socket, "getaddrinfo", fake):
            r = SourceVerifier().verify("http://mapped.example.com/x")
        self.assertIsNone(r["ok"])
        self.assertEqual(r["outcome"], "blocked")
        self.assertIn("policy-blocked", r["error"])

    def test_pin_cache_shared_between_head_and_get(self):
        # One verify() = HEAD + GET. The pin resolved for HEAD must be reused
        # for GET (no second resolution inside the TTL), closing the flip
        # window. Count only resolver invocations by the policy layer (not the
        # ones inside socket.create_connection).
        import verify as verify_module
        resolve_calls = []
        real_resolve = verify_module._resolve_pinned

        def counting(hostname, port, allow_private):
            resolve_calls.append(hostname)
            return real_resolve(hostname, port, allow_private)

        with self._direct_network(), \
             mock.patch.object(verify_module, "_resolve_pinned", counting):
            v = SourceVerifier(allow_private_networks=True)
            v.verify("http://127.0.0.1:9/x")  # dial refused; pin resolved once
        self.assertEqual(len(resolve_calls), 1,
                         f"expected a single resolution, got {resolve_calls}")

    def test_get_transport_failure_stays_unknown(self):
        # Transport-level URLError (connection refused, hits the HEAD stage
        # first) is uncertainty, not proof of death: ok must stay None, and
        # must never be confused with the deterministic policy-blocked state
        # (ok=None + outcome="blocked"). The GET stage mirrors this with a
        # "body-fetch-network-unavailable" prefix.
        with self._direct_network():
            r = SourceVerifier(allow_private_networks=True).verify("http://127.0.0.1:9/x")
        self.assertIsNone(r["ok"], "transport failure must be unknown, not dead")
        self.assertIn("network-unavailable", r["error"])
        self.assertNotIn("policy-blocked", r["error"])

    # ---- external-review findings (GodBlf, 2026-09-20) --------------------

    def test_head_ok_then_get_success_shares_one_pin(self):
        # Evidence gap: the pin-sharing test above stops at a refused HEAD, so
        # HEAD→GET on a *successful* path was never exercised. Here HEAD 200 is
        # followed by a real GET 200; both must reuse one resolution.
        import verify as verify_module
        resolve_calls = []
        real_resolve = verify_module._resolve_pinned

        def counting(hostname, port, allow_private):
            resolve_calls.append(hostname)
            return real_resolve(hostname, port, allow_private)

        with tempfile.TemporaryDirectory() as td:
            Path(td, "doc.txt").write_text("pin me", encoding="utf-8")
            expected = hashlib.sha256(b"pin me").hexdigest()
            srv = LocalServer(td)
            try:
                with self._direct_network(), \
                     mock.patch.object(verify_module, "_resolve_pinned", counting):
                    r = SourceVerifier(allow_private_networks=True).verify(srv.url("doc.txt"))
            finally:
                srv.close()
        self.assertTrue(r["ok"], r)
        self.assertEqual(r["outcome"], "alive")
        self.assertEqual(r["sha256"], expected)
        self.assertEqual(len(resolve_calls), 1,
                         f"HEAD and GET must share one resolution, got {resolve_calls}")

    def test_head_ok_then_get_timeout_is_unknown_not_success(self):
        # Finding 2: HEAD mocked 200 then GET raises TimeoutError. The generic
        # GET handler used to leave ok=True from the HEAD stage, so the summary
        # reported alive=1 / degraded=False for a run that never verified the
        # body. It must degrade to unknown.
        import verify as verify_module

        def fake_request(self, req, read_body):
            if not read_body:
                return 200, {}, b""
            raise TimeoutError("read timed out")

        with mock.patch.object(verify_module.SourceVerifier, "_request", fake_request):
            v = SourceVerifier(allow_private_networks=True)
            r = v.verify("http://public.example.com/x")
            s = v.summary([r])
        self.assertIsNone(r["ok"], "unverifiable content must not be a success")
        self.assertEqual(r["outcome"], "unknown")
        self.assertIn("body-fetch-failed", r["error"])
        self.assertNotEqual(s["alive"], 1)
        self.assertEqual((s["alive"], s["dead"], s["unknown"]), (0, 0, 1))
        self.assertTrue(s["degraded"], "an unverified body must degrade the run")

    def test_policy_blocked_is_not_counted_as_dead(self):
        # Finding 3: a policy decision not to access a source must not be
        # aggregated as a dead source.
        with self._direct_network():
            v = SourceVerifier()
            r = v.verify("http://127.0.0.1:9/x")
            s = v.summary([r])
        self.assertEqual(r["outcome"], "blocked")
        self.assertEqual(s["dead"], 0, "a policy block is not evidence of death")
        self.assertEqual(s["blocked"], 1)
        self.assertTrue(s["degraded"])
        self.assertNotIn("policy_failure", s)

    def test_fail_on_policy_block_is_explicit_opt_in(self):
        # Failing a run on a policy block is a configured choice, never an
        # emergent artefact of the aggregation.
        with self._direct_network():
            v = SourceVerifier(fail_on_policy_block=True)
            r = v.verify("http://127.0.0.1:9/x")
            s = v.summary([r])
        self.assertEqual(s["blocked"], 1)
        self.assertTrue(s.get("policy_failure"),
                        "fail_on_policy_block must surface a policy failure")

    def test_restricted_mode_redirect_to_private_target_is_blocked(self):
        # Evidence gap: the existing redirect test enables private networks.
        # Here hop 1 resolves public (rewired onto the local server) and the
        # redirect points at a private target, which restricted mode must
        # refuse — as "blocked", never as "dead".
        class _Redirect(http.server.BaseHTTPRequestHandler):
            def _redirect(self):
                self.send_response(302)
                self.send_header(
                    "Location",
                    f"http://private.example.com:{self.server.server_address[1]}/x")
                self.send_header("Content-Length", "0")
                self.end_headers()

            do_HEAD = _redirect
            do_GET = _redirect

            def log_message(self, *a):
                pass

        httpd = socketserver.TCPServer(("127.0.0.1", 0), _Redirect)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        port = httpd.server_address[1]
        fake_resolve = self._fake_resolver({"public.example.com": self.PUBLIC_IP,
                                            "private.example.com": "10.0.0.5"})
        real_create = socket.create_connection

        def rewire(address, timeout=None, source_address=None):
            host, prt = address
            if host == self.PUBLIC_IP:      # land hop 1 on the local server
                return real_create(("127.0.0.1", prt), timeout=timeout,
                                   source_address=source_address)
            raise AssertionError(f"unexpected dial to {address}")

        try:
            with self._direct_network(), \
                 mock.patch.object(socket, "getaddrinfo", fake_resolve), \
                 mock.patch.object(socket, "create_connection", rewire):
                r = SourceVerifier().verify(f"http://public.example.com:{port}/x")
        finally:
            httpd.shutdown()
            httpd.server_close()
        self.assertEqual(r.get("outcome"), "blocked", r)
        self.assertIsNone(r["ok"])
        self.assertTrue(r["error"].startswith("policy-blocked"), r["error"])


class TestProxyPolicyFailClosed(unittest.TestCase):
    """Finding 1: a configured proxy takes DNS away from the verifier, so
    restricted mode must reject the configuration instead of silently running
    an unpinned opener."""

    PUBLIC_URL = "http://public.example.com/x"

    @contextmanager
    def _clean_proxy_env(self):
        keys = ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy",
                "ALL_PROXY", "all_proxy", "NO_PROXY", "no_proxy"]
        saved = {k: os.environ.pop(k) for k in keys if k in os.environ}
        try:
            yield
        finally:
            os.environ.update(saved)

    def test_restricted_mode_rejects_explicit_proxy(self):
        with self._clean_proxy_env():
            r = SourceVerifier(proxy="http://127.0.0.1:9").verify(self.PUBLIC_URL)
        self.assertIsNone(r["ok"], "a rejected config is not a liveness claim")
        self.assertEqual(r["outcome"], "unknown")
        self.assertTrue(r["error"].startswith("proxy-policy-unsupported"),
                        r["error"])

    def test_restricted_mode_rejects_environment_proxy(self):
        with self._clean_proxy_env(), \
             mock.patch.object(urllib.request, "getproxies",
                               return_value={"http": "http://127.0.0.1:9"}):
            r = SourceVerifier().verify(self.PUBLIC_URL)
        self.assertIsNone(r["ok"])
        self.assertEqual(r["outcome"], "unknown")
        self.assertTrue(r["error"].startswith("proxy-policy-unsupported"),
                        r["error"])

    def test_env_proxy_does_not_bypass_validation_when_proxied_url_is_plain(self):
        # Regression on the old fallback: with an env proxy configured, the
        # restricted path must never hand the request to a bare (unpinned)
        # opener. Both stages must refuse, not fall back.
        import verify as verify_module
        with self._clean_proxy_env(), \
             mock.patch.object(urllib.request, "getproxies",
                               return_value={"https": "http://127.0.0.1:9"}):
            with self.assertRaises(verify_module._ProxyPolicyUnsupported):
                verify_module._build_opener(self.PUBLIC_URL, None, None, None)

    def test_no_proxy_matched_url_keeps_the_pinned_path(self):
        # NO_PROXY-matched URLs never traverse the egress proxy, so they must
        # keep the pinned handlers rather than being rejected.
        import verify as verify_module
        v = SourceVerifier(allow_private_networks=True)
        with self._clean_proxy_env(), \
             mock.patch.dict(os.environ, {"NO_PROXY": "example.com"}), \
             mock.patch.object(urllib.request, "getproxies",
                               return_value={"http": "http://127.0.0.1:9"}):
            opener = verify_module._build_opener(
                self.PUBLIC_URL, None, v._http_handler, v._https_handler)
        self.assertIsNotNone(opener)

    def test_explicit_proxy_allowed_when_opted_in(self):
        # allow_private_networks=True is the documented escape hatch: it says
        # "I accept that through a proxy, DNS pinning does not run". The fetch
        # then fails on the dead proxy (unknown), not on the policy.
        with self._clean_proxy_env():
            r = SourceVerifier(proxy="http://127.0.0.1:9",
                               allow_private_networks=True).verify(self.PUBLIC_URL)
        self.assertNotIn("proxy-policy-unsupported", r["error"])
        self.assertIsNone(r["ok"])


if __name__ == "__main__":
    unittest.main()
