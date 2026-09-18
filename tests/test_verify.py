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
        self.assertFalse(r["ok"])
        self.assertTrue(r["error"].startswith("policy-blocked"),
                        f"expected policy-blocked, got {r['error']!r}")

    def test_private_resolving_hostname_blocked(self):
        fake = self._fake_resolver({"private.example.com": "10.0.0.5"})
        with self._direct_network(), mock.patch.object(socket, "getaddrinfo", fake):
            r = SourceVerifier().verify("http://private.example.com/x")
        self.assertFalse(r["ok"])
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
        self.assertFalse(r["ok"])
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
        # (ok=False). The GET stage mirrors this with a
        # "body-fetch-network-unavailable" prefix.
        with self._direct_network():
            r = SourceVerifier(allow_private_networks=True).verify("http://127.0.0.1:9/x")
        self.assertIsNone(r["ok"], "transport failure must be unknown, not dead")
        self.assertIn("network-unavailable", r["error"])
        self.assertNotIn("policy-blocked", r["error"])


if __name__ == "__main__":
    unittest.main()
