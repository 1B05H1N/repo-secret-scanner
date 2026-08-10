import unittest

import secret_scanner as ss


class EntropyTests(unittest.TestCase):
    def test_entropy_low_for_repetition(self):
        self.assertLess(ss.shannon_entropy("aaaaaaaa"), 1.0)

    def test_entropy_high_for_random(self):
        self.assertGreater(ss.shannon_entropy("Gh7kLp2QwZ9rXt4Bv"), 3.0)


class RedactTests(unittest.TestCase):
    def test_never_reveals_full_secret(self):
        secret = "AKIAIOSFODNN7EXAMPLE"
        out = ss.redact(secret)
        self.assertNotIn(secret, out)
        self.assertTrue(out.startswith("AKI"))

    def test_short_fully_masked(self):
        self.assertEqual(ss.redact("abc"), "***")


class ScanTests(unittest.TestCase):
    def test_detects_aws_key(self):
        findings = ss.scan_text("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE")
        rules = {f["rule"] for f in findings}
        self.assertIn("aws_access_key_id", rules)

    def test_detects_private_key(self):
        findings = ss.scan_text("-----BEGIN RSA PRIVATE KEY-----")
        self.assertTrue(any(f["rule"] == "private_key_block" for f in findings))

    def test_detects_assigned_secret_high_entropy(self):
        findings = ss.scan_text('db_password = "Gh7kLp2QwZ9rXt4Bv"')
        assigned = [f for f in findings if f["rule"].startswith("assigned_secret")]
        self.assertTrue(assigned)
        self.assertEqual(assigned[0]["severity"], "high")

    def test_placeholder_ignored(self):
        findings = ss.scan_text('api_token = "changeme"')
        self.assertEqual(findings, [])

    def test_allowlist_marker_skips_line(self):
        findings = ss.scan_text('secret = "Qp9zR2mK7wLx4Tn8Vb3Yc"  # allowlist secret')
        self.assertEqual(findings, [])

    def test_output_is_redacted(self):
        findings = ss.scan_text('token = "Gh7kLp2QwZ9rXt4Bv"')
        for f in findings:
            self.assertNotIn("Gh7kLp2QwZ9rXt4Bv", f["match"])


if __name__ == "__main__":
    unittest.main()
