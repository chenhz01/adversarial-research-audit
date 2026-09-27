"""Redirect policy checks with no network connections or large allocations."""
from __future__ import annotations

import os
import sys
import unittest
import urllib.error
import urllib.request
from email.message import Message
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import verify


class TestRedirectSafety(unittest.TestCase):
    MODES = ("direct", "loopback", "no-proxy",
             "explicit-proxy-opt-in", "environment-proxy-opt-in")
    CODES = (301, 302, 303, 307, 308)

    def handler(self, mode):
        url = ("http://127.0.0.1/source" if mode == "loopback"
               else "http://source.audit.test/source")
        proxy = "http://127.0.0.1:9" if mode == "explicit-proxy-opt-in" else None
        proxies = {"http": "http://127.0.0.1:9"} if mode in {
            "no-proxy", "environment-proxy-opt-in"} else {}
        bypass = "source.audit.test" if mode == "no-proxy" else ""
        env = {"NO_PROXY": bypass, "no_proxy": bypass}
        verifier = verify.SourceVerifier()
        with mock.patch.dict(os.environ, env), mock.patch.object(
                urllib.request, "getproxies", return_value=proxies):
            opener = verify._build_opener(
                url, proxy, verifier._http_handler, verifier._https_handler,
                allow_private_networks=mode.endswith("opt-in"))
        handlers = [h for h in opener.handlers
                    if isinstance(h, urllib.request.HTTPRedirectHandler)]
        self.assertEqual(len(handlers), 1)
        handler = handlers[0]
        handler.parent = mock.Mock()
        request = urllib.request.Request(url, method="GET")
        request.timeout = 1
        return handler, request

    @staticmethod
    def headers(target, name="Location"):
        headers = Message()
        headers[name] = target
        return headers

    def test_non_http_schemes_are_blocked_in_every_opener(self):
        targets = ("ftp://127.0.0.1:21/file", "FTP://127.0.0.1/file",
                   "file:///private/file", "data:text/plain,payload",
                   "gopher://127.0.0.1/file")
        for mode in self.MODES:
            for code in self.CODES:
                for header in ("Location", "URI"):
                    for target in targets:
                        with self.subTest(mode=mode, code=code, header=header, target=target):
                            handler, request = self.handler(mode)
                            response = mock.Mock()
                            response.read.return_value = b""
                            method = getattr(handler, f"http_error_{code}")
                            with self.assertRaises(verify._PolicyBlocked):
                                method(request, response, code, "Redirect",
                                       self.headers(target, header))
                            response.close.assert_called_once()
                            response.read.assert_not_called()
                            handler.parent.open.assert_not_called()

    def test_http_redirects_discard_body_and_preserve_url_resolution(self):
        targets = {
            "/final": "http://source.audit.test/final",
            "//other.audit.test/final": "http://other.audit.test/final",
            "http://other.audit.test/final": "http://other.audit.test/final",
            "https://other.audit.test/final": "https://other.audit.test/final",
        }
        for mode in self.MODES:
            for code in self.CODES:
                for target, expected in targets.items():
                    with self.subTest(mode=mode, code=code, target=target):
                        handler, request = self.handler(mode)
                        response = mock.Mock()
                        response.read.side_effect = AssertionError(
                            "intermediate body must not be read")
                        method = getattr(handler, f"http_error_{code}")
                        result = method(request, response, code, "Redirect",
                                        self.headers(target))
                        self.assertIs(result, handler.parent.open.return_value)
                        redirected = handler.parent.open.call_args.args[0]
                        if mode == "loopback" and target == "/final":
                            expected = "http://127.0.0.1/final"
                        self.assertEqual(redirected.full_url, expected)
                        response.close.assert_called_once()
                        response.read.assert_not_called()

    def test_redirect_loop_limit_is_preserved_and_response_closed(self):
        handler, request = self.handler("direct")
        target = "http://source.audit.test/final"
        request.redirect_dict = {target: handler.max_repeats}
        response = mock.Mock()
        with self.assertRaises(urllib.error.HTTPError):
            handler.http_error_302(request, response, 302, "Redirect",
                                   self.headers(target))
        handler.parent.open.assert_not_called()
        response.read.assert_not_called()
        response.close.assert_called_once()

    def test_missing_location_still_closes_response(self):
        handler, request = self.handler("direct")
        response = mock.Mock()
        self.assertIsNone(handler.http_error_302(
            request, response, 302, "Redirect", Message()))
        handler.parent.open.assert_not_called()
        response.read.assert_not_called()
        response.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
