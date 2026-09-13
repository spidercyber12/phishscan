"""Unit test untuk analyzers.url_parser."""
import sys
import os
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analyzers.url_parser import analyze


class TestURLParser(unittest.TestCase):

    def test_simple_url(self):
        r = analyze("http://example.com")
        self.assertEqual(r["scheme"], "http")
        self.assertEqual(r["host"], "example.com")
        self.assertEqual(r["domain"], "example")
        self.assertEqual(r["suffix"], "com")
        self.assertFalse(r["flags"]["is_https"])

    def test_https_flag(self):
        r = analyze("https://example.com")
        self.assertTrue(r["flags"]["is_https"])

    def test_auto_scheme(self):
        r = analyze("example.com")
        self.assertEqual(r["scheme"], "http")
        self.assertEqual(r["host"], "example.com")

    def test_ip_host(self):
        r = analyze("http://192.168.1.1/login")
        self.assertTrue(r["flags"]["is_ip"])
        self.assertEqual(r["host"], "192.168.1.1")
        self.assertEqual(r["registered_domain"], "192.168.1.1")
        self.assertEqual(r["subdomain"], "")
        self.assertEqual(r["domain"], "")

    def test_multi_level_suffix(self):
        r = analyze("https://login.bank.co.id/verify")
        self.assertEqual(r["subdomain"], "login")
        self.assertEqual(r["domain"], "bank")
        self.assertEqual(r["suffix"], "co.id")
        self.assertEqual(r["registered_domain"], "bank.co.id")

    def test_shortener_detected(self):
        r = analyze("https://bit.ly/abc")
        self.assertTrue(r["flags"]["is_shortener"])

    def test_at_sign(self):
        r = analyze("http://google.com@evil.com/")
        self.assertTrue(r["flags"]["has_at"])
        self.assertEqual(r["host"], "evil.com")

    def test_many_subdomains(self):
        r = analyze("http://a.b.c.d.example.com/")
        self.assertGreaterEqual(r["flags"]["num_subdomains"], 3)

    def test_custom_port(self):
        r = analyze("http://example.com:8080/")
        self.assertTrue(r["flags"]["has_port"])
        self.assertEqual(r["port"], 8080)

    def test_path_and_query(self):
        r = analyze("http://example.com/login?id=1&x=2")
        self.assertEqual(r["path"], "/login")
        self.assertEqual(r["query"], "id=1&x=2")

    def test_empty_path_becomes_slash(self):
        r = analyze("http://example.com")
        self.assertEqual(r["path"], "/")


if __name__ == "__main__":
    unittest.main()
