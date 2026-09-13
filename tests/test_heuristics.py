"""Unit test untuk analyzers.heuristics."""
import sys
import os
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analyzers.url_parser import analyze as parse_url
from analyzers.heuristics import analyze as run_heuristics


def codes_for(url):
    return {i["code"] for i in run_heuristics(parse_url(url))["indicators"]}


class TestHeuristics(unittest.TestCase):

    def test_clean_url_no_indicators(self):
        self.assertEqual(codes_for("https://google.com"), set())

    def test_http_no_tls(self):
        self.assertIn("HTTP_NO_TLS", codes_for("http://example.com"))

    def test_ip_host(self):
        self.assertIn("IP_HOST", codes_for("http://192.168.1.1/"))

    def test_shortener(self):
        self.assertIn("SHORTENER", codes_for("https://bit.ly/abc"))

    def test_at_in_url(self):
        self.assertIn("AT_IN_URL", codes_for("http://google.com@evil.com/"))

    def test_suspicious_tld(self):
        self.assertIn("SUSPICIOUS_TLD", codes_for("http://example.tk/"))

    def test_suspicious_keyword(self):
        self.assertIn("SUSPICIOUS_KEYWORD", codes_for("http://example.com/login"))

    def test_typosquat_paypa1(self):
        self.assertIn("TYPOSQUAT", codes_for("http://paypa1.tk/"))

    def test_typosquat_deleet_faceb00k(self):
        self.assertIn("TYPOSQUAT", codes_for("http://faceb00k.tk/"))

    def test_brand_misuse_subdomain(self):
        self.assertIn("BRAND_MISUSE", codes_for("https://paypal.evil.com"))

    def test_dangerous_file(self):
        self.assertIn("DANGEROUS_FILE", codes_for("http://example.com/setup.exe"))

    def test_long_url(self):
        u = "http://example.com/" + ("a" * 100)
        self.assertIn("LONG_URL", codes_for(u))

    def test_no_typosquat_for_real_domain(self):
        self.assertNotIn("TYPOSQUAT", codes_for("https://paypal.com"))

    def test_clean_domain_no_typosquat(self):
        codes = codes_for("https://kucing.com")
        self.assertNotIn("TYPOSQUAT", codes)
        self.assertNotIn("BRAND_MISUSE", codes)


if __name__ == "__main__":
    unittest.main()
