import hashlib
import tempfile
import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from dfit import sha256_file, triage_flags, analyze, identify_file_signature, find_duplicate_groups


class TestDFIT(unittest.TestCase):
    def test_sha256_matches_known_value(self):
        with tempfile.TemporaryDirectory() as tmp:
            file_path = Path(tmp) / "sample.txt"
            file_path.write_text("hello", encoding="utf-8")
            self.assertEqual(sha256_file(file_path), hashlib.sha256(b"hello").hexdigest())

    def test_executable_extension_is_flagged(self):
        self.assertTrue(any("Review file type" in flag for flag in triage_flags(Path("sample.exe"))))

    def test_hidden_name_is_flagged(self):
        self.assertIn("Hidden-style filename", triage_flags(Path(".hidden.txt")))

    def test_analysis_creates_reports(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "evidence"
            output = root / "reports"
            source.mkdir()
            (source / "notes.txt").write_text("practice evidence", encoding="utf-8")
            result = analyze(source, "TEST-01", "Tester", "unit test", output)
            self.assertTrue((result / "evidence_inventory.csv").exists())
            self.assertTrue((result / "timeline.csv").exists())
            self.assertTrue((result / "case_report.json").exists())
            self.assertTrue((result / "case_report.txt").exists())


    def test_pdf_signature_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            file_path = Path(tmp) / "sample.pdf"
            file_path.write_bytes(b"%PDF-1.7 sample")
            detected, status = identify_file_signature(file_path)
            self.assertEqual(detected, "PDF document")
            self.assertIn("matches", status)

    def test_duplicate_hashes_grouped(self):
        sample = [
            {"sha256": "abc", "relative_path": "a.txt"},
            {"sha256": "abc", "relative_path": "copy.txt"},
            {"sha256": "xyz", "relative_path": "b.txt"},
        ]
        groups = find_duplicate_groups(sample)
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0]["count"], 2)


if __name__ == "__main__":
    unittest.main()
