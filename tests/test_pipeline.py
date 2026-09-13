"""Smoke test untuk pipeline."""
import sys
import os
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pipeline import run


class TestPipelineSmoke(unittest.TestCase):

    def test_run_returns_expected_keys(self):
        r = run("http://thisdomaindoesnotexist-xyz123.tk/login")
        self.assertIn("url", r)
        self.assertIn("score", r)
        self.assertIn("verdict", r)
        self.assertIn("indicators", r)
        self.assertIn("notes", r)
        self.assertIn("steps", r)

    def test_phishing_typosquat_scores_high(self):
        r = run("http://paypa1-login.tk/verify")
        self.assertGreaterEqual(r["score"], 60)
        self.assertIn(r["verdict"], ("likely_phishing", "dangerous"))

    def test_ip_private_blocked(self):
        r = run("http://192.168.1.1/login.exe")
        codes = {i["code"] for i in r["indicators"]}
        self.assertIn("SSRF_BLOCKED", codes)
        self.assertIn("IP_HOST", codes)

    def test_steps_contains_all_modules(self):
        r = run("http://thisdomaindoesnotexist-xyz123.tk/")
        steps = r["steps"]
        for name in ("url_parser", "heuristics", "dns", "ssl", "redirect", "html"):
            self.assertIn(name, steps)

    def test_url_without_scheme(self):
        r = run("thisdomaindoesnotexist-xyz123.tk")
        self.assertIn("score", r)


if __name__ == "__main__":
    unittest.main()
