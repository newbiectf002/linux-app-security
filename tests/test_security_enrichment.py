from __future__ import annotations

import unittest
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts" / "lib"))

from security_enrichment import _checksec_summary, _string_review  # noqa: E402


class SecurityEnrichmentTests(unittest.TestCase):
    def test_strings_keep_only_high_signal_review_cues(self) -> None:
        output = "\n".join([
            "https://gnu.org/licenses/gpl.html",
            "http://127.0.0.1/debug",
            "/usr/lib/libc.so.6",
            "/home/builder/product/source.c",
            "-----BEGIN PRIVATE KEY-----",
        ])
        items = _string_review(output, "ev-strings")
        values = [item["value"] for item in items]

        self.assertNotIn("https://gnu.org/licenses/gpl.html", values)
        self.assertNotIn("/usr/lib/libc.so.6", values)
        self.assertIn("http://127.0.0.1/debug", values)
        self.assertIn("/home/builder/product/source.c", values)
        self.assertIn("-----BEGIN PRIVATE KEY-----", values)
        self.assertTrue(all(item["evidence_ref"] == "ev-strings" for item in items))

    def test_checksec_v3_json_is_compacted(self) -> None:
        result = _checksec_summary(
            '[{"name":"/bin/app","checks":{"nx":{"value":"NX enabled"},'
            '"pie":{"value":"PIE Enabled"},"safestack":{"value":"No"}}}]'
        )

        self.assertEqual({"value": "NX enabled"}, result["nx"])
        self.assertEqual({"value": "PIE Enabled"}, result["pie"])
        self.assertNotIn("safestack", result)


if __name__ == "__main__":
    unittest.main()
