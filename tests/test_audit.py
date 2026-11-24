"""Unit tests for the Vibe-to-Production static security auditor."""

from pathlib import Path
import tempfile
import unittest

from auditor.scanner import scan_directory
from vibe_audit import main


class AuditScannerTests(unittest.TestCase):
    def test_clean_directory_scores_100(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.ts").write_text("export const status = 'healthy';\n", encoding="utf-8")
            (root / "schema.sql").write_text(
                "ALTER TABLE projects ENABLE ROW LEVEL SECURITY;\n", encoding="utf-8"
            )

            report = scan_directory(root)
            self.assertEqual(report["score"], 100)
            self.assertEqual(report["finding_count"], 0)
            self.assertTrue(report["passed"])

    def test_detects_client_secret_and_rls_bypass(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            # Dynamically build synthetic marker so literal repo regexes stay clean
            prefix = "NEXT_PUBLIC_" + "SUPABASE_SERVICE_ROLE_KEY"
            (root / "client.ts").write_text(f"const k = process.env.{prefix};\n", encoding="utf-8")
            (root / "bad.sql").write_text(
                "ALTER TABLE invoices DISABLE ROW LEVEL SECURITY;\n", encoding="utf-8"
            )

            report = scan_directory(root)
            rule_ids = {f["rule_id"] for f in report["findings"]}
            self.assertIn("VIBE-001", rule_ids)
            self.assertIn("VIBE-003", rule_ids)
            self.assertLess(report["score"], 80)

    def test_cli_returns_non_zero_below_threshold(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            snippet = "import requests\nrequests.get('https://example.com', " + "verify=" + "False)\n"
            (root / "tls.py").write_text(snippet, encoding="utf-8")
            exit_code = main([str(root), "--fail-under", "95"])
            self.assertEqual(exit_code, 1)


if __name__ == "__main__":
    unittest.main()
