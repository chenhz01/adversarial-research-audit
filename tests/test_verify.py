"""Tests for source authenticity verification (verify.py).
Uses a local HTTP server so no external network is required."""
from __future__ import annotations

import functools
import hashlib
import http.server
import socketserver
import urllib.error
import urllib.request
import sys
import tempfile
import threading
import unittest
from unittest import mock
from pathlib import Path

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
        v = SourceVerifier()
        r = v.verify(self.srv.url("exists.txt"))
        self.assertTrue(r["ok"])
        self.assertEqual(r["status_code"], 200)
        self.assertEqual(r["sha256"], self.expected_sha)
        self.assertEqual(r["bytes"], len(b"hello authenticity"))

    def test_hash_match_flag(self):
        v = SourceVerifier()
        good = v.verify(self.srv.url("exists.txt"), expect_sha256=self.expected_sha)
        self.assertTrue(good["hash_match"])
        bad = v.verify(self.srv.url("exists.txt"), expect_sha256="0" * 64)
        self.assertFalse(bad["hash_match"])

    def test_dead_url(self):
        v = SourceVerifier()
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
        v = SourceVerifier()
        results = [v.verify(self.srv.url("exists.txt")),
                   v.verify(self.srv.url("gone.txt"))]
        s = v.summary(results)
        self.assertEqual((s["total"], s["alive"], s["dead"]), (2, 1, 1))
        self.assertFalse(s["degraded"])
        s2 = v.summary([SourceVerifier(offline=True).verify("http://x/y")])
        self.assertTrue(s2["degraded"])

    def test_bad_scheme_rejected(self):
        r = SourceVerifier().verify("raw/sources/local.md")
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
            r = SourceVerifier().verify(f"http://127.0.0.1:{srv.port}/anything")
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
                    r = SourceVerifier().verify(srv.url("f.txt"))
                    self.assertTrue(r["ok"], "loopback must bypass HTTP_PROXY")
                    self.assertFalse(r["via_proxy"])
                finally:
                    srv.close()
        finally:
            os.environ.pop("HTTP_PROXY", None)


class TestMcpNetworkPolicy(unittest.TestCase):
    def test_private_literal_is_unknown_when_private_networks_are_blocked(self):
        result = SourceVerifier(allow_private_networks=False).verify("http://127.0.0.1/private")
        self.assertIsNone(result["ok"])
        self.assertEqual(result["error"], "blocked-private-address")

    def test_private_dns_result_is_unknown(self):
        with mock.patch(
            "verify.socket.getaddrinfo",
            return_value=[(None, None, None, None, ("10.0.0.2", 80))],
        ):
            result = SourceVerifier(allow_private_networks=False).verify("http://internal.example/a")
        self.assertIsNone(result["ok"])
        self.assertEqual(result["error"], "blocked-private-address")

    def test_redirect_target_is_revalidated(self):
        verifier = SourceVerifier(allow_private_networks=False)
        handler = verifier._redirect_handler()
        request = urllib.request.Request("https://public.example/start")
        with mock.patch(
            "verify.socket.getaddrinfo",
            return_value=[(None, None, None, None, ("127.0.0.1", 80))],
        ):
            with self.assertRaises(urllib.error.URLError):
                handler.redirect_request(request, None, 302, "Found", {}, "http://localhost/admin")

    def test_body_transport_failure_is_unknown(self):
        verifier = SourceVerifier()
        with mock.patch.object(
            verifier,
            "_request",
            side_effect=[(200, {}, b""), urllib.error.URLError("offline")],
        ):
            result = verifier.verify("https://example.com/source", use_cache=False)
        self.assertIsNone(result["ok"])
        self.assertIn("body-fetch-failed", result["error"])


if __name__ == "__main__":
    unittest.main()
