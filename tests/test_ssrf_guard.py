"""Unit test untuk analyzers.ssrf_guard."""
import sys
import os
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analyzers.ssrf_guard import check_host


class TestSSRFGuard(unittest.TestCase):

    def test_localhost_blocked(self):
        ok, reason, ips, ssrf = check_host("localhost")
        self.assertFalse(ok)
        self.assertTrue(ssrf)

    def test_127_0_0_1_blocked(self):
        ok, _, _, ssrf = check_host("127.0.0.1")
        self.assertFalse(ok)
        self.assertTrue(ssrf)

    def test_private_10_blocked(self):
        ok, _, _, ssrf = check_host("10.0.0.1")
        self.assertFalse(ok)
        self.assertTrue(ssrf)

    def test_private_192_168_blocked(self):
        ok, _, _, ssrf = check_host("192.168.1.1")
        self.assertFalse(ok)
        self.assertTrue(ssrf)

    def test_metadata_blocked(self):
        ok, _, _, ssrf = check_host("169.254.169.254")
        self.assertFalse(ok)
        self.assertTrue(ssrf)

    def test_public_ip_allowed(self):
        ok, _, ips, ssrf = check_host("8.8.8.8")
        self.assertTrue(ok)
        self.assertFalse(ssrf)
        self.assertIn("8.8.8.8", ips)

    def test_unresolved_not_ssrf(self):
        ok, reason, ips, ssrf = check_host("thisdomaindoesnotexist-xyz123.tk")
        self.assertFalse(ok)
        self.assertFalse(ssrf)

    def test_empty_host(self):
        ok, _, _, ssrf = check_host("")
        self.assertFalse(ok)


if __name__ == "__main__":
    unittest.main()
