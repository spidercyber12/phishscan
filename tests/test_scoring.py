"""Unit test untuk scoring.engine."""
import sys
import os
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scoring.engine import score_indicators, _dedup_and_cap


def ind(code, sev, label="x"):
    return {"code": code, "label": label, "severity": sev, "detail": ""}


class TestScoring(unittest.TestCase):

    def test_no_indicators_safe(self):
        r = score_indicators([])
        self.assertEqual(r["score"], 0)
        self.assertEqual(r["verdict"], "safe")

    def test_low_severity_suspicious(self):
        r = score_indicators([ind("A", 20)])
        self.assertEqual(r["verdict"], "suspicious")

    def test_medium_severity_likely_phishing(self):
        r = score_indicators([ind("A", 50)])
        self.assertEqual(r["verdict"], "likely_phishing")

    def test_high_severity_dangerous(self):
        r = score_indicators([ind("A", 80)])
        self.assertEqual(r["verdict"], "dangerous")

    def test_score_capped_at_100(self):
        r = score_indicators([ind("A", 90), ind("B", 90), ind("C", 90)])
        self.assertEqual(r["score"], 100)

    def test_dedup_keeps_highest(self):
        deduped = _dedup_and_cap([ind("A", 10), ind("A", 40), ind("A", 20)])
        self.assertEqual(len(deduped), 1)
        self.assertEqual(deduped[0]["severity"], 40)

    def test_suspicious_keyword_capped(self):
        deduped = _dedup_and_cap([ind("SUSPICIOUS_KEYWORD", 100)])
        self.assertEqual(deduped[0]["severity"], 25)

    def test_combination_bonus_typosquat_keyword(self):
        r = score_indicators([ind("TYPOSQUAT", 45), ind("SUSPICIOUS_KEYWORD", 15)])
        self.assertGreaterEqual(r["score"], 75)
        self.assertTrue(any("typosquat" in n.lower() for n in r["notes"]))

    def test_unresolved_suppresses_html_fetch_fail(self):
        r = score_indicators([
            ind("UNRESOLVED", 30),
            ind("HTML_FETCH_FAIL", 5),
            ind("NO_TLS_CERT", 25),
        ])
        codes = {i["code"] for i in r["indicators"]}
        self.assertIn("UNRESOLVED", codes)
        self.assertNotIn("HTML_FETCH_FAIL", codes)
        self.assertNotIn("NO_TLS_CERT", codes)


if __name__ == "__main__":
    unittest.main()
