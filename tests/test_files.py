import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path

from cybersec_toolkit.files import (
    create_integrity_manifest,
    find_duplicate_files,
    sha256_file,
    verify_integrity_manifest,
)


class FileIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "nested").mkdir()
        (self.root / "nested" / "sample.bin").write_bytes(b"test\x00data")
        (self.root / "another.txt").write_text("Another file", encoding="utf-8")

    def test_streaming_hash_and_json_manifest_round_trip(self):
        digest = hashlib.sha256(b"test\x00data").hexdigest()
        self.assertEqual(sha256_file(self.root / "nested" / "sample.bin"), digest)
        manifest = create_integrity_manifest(
            ["nested/sample.bin", self.root / "another.txt"], self.root
        )
        self.assertEqual(manifest["schema_version"], 1)
        entries = {entry["path"]: entry for entry in manifest["files"]}
        self.assertEqual(entries["nested/sample.bin"]["sha256"], digest)
        self.assertEqual(entries["nested/sample.bin"]["size_bytes"], 9)
        loaded = json.loads(json.dumps(manifest))
        self.assertEqual(
            verify_integrity_manifest(loaded, self.root),
            {"ok": True, "checked": 2, "missing": [], "modified": []},
        )

    def test_reports_changed_and_missing_files(self):
        manifest = create_integrity_manifest(
            ["nested/sample.bin", "another.txt"], self.root
        )
        (self.root / "nested" / "sample.bin").write_bytes(b"different")
        (self.root / "another.txt").unlink()
        result = verify_integrity_manifest(manifest, self.root)
        self.assertFalse(result["ok"])
        self.assertEqual(result["missing"], ["another.txt"])
        self.assertEqual(result["modified"], ["nested/sample.bin"])

    def test_rejects_traversal_and_duplicate_paths(self):
        with self.assertRaises(ValueError):
            create_integrity_manifest(["../outside.txt"], self.root)
        with self.assertRaises(ValueError):
            create_integrity_manifest(["another.txt", "another.txt"], self.root)
        manifest = create_integrity_manifest(["another.txt"], self.root)
        for unsafe in ("../another.txt", "/etc/passwd", "C:\\windows\\system.ini"):
            broken = json.loads(json.dumps(manifest))
            broken["files"][0]["path"] = unsafe
            with self.subTest(unsafe=unsafe), self.assertRaises(ValueError):
                verify_integrity_manifest(broken, self.root)
        broken = json.loads(json.dumps(manifest))
        broken["files"].append(dict(broken["files"][0]))
        with self.assertRaisesRegex(ValueError, "duplicate"):
            verify_integrity_manifest(broken, self.root)

    def test_rejects_malformed_digest_and_symlink(self):
        manifest = create_integrity_manifest(["another.txt"], self.root)
        manifest["files"][0]["sha256"] = "bad"
        with self.assertRaisesRegex(ValueError, "digest"):
            verify_integrity_manifest(manifest, self.root)
        link = self.root / "shortcut.txt"
        try:
            link.symlink_to(self.root / "another.txt")
        except (OSError, NotImplementedError):
            return
        with self.assertRaisesRegex(ValueError, "symlinks"):
            create_integrity_manifest(["shortcut.txt"], self.root)

    def test_groups_duplicate_content(self):
        first = self.root / "first.txt"
        second = self.root / "second.txt"
        unique = self.root / "unique.txt"
        first.write_text("same", encoding="utf-8")
        second.write_text("same", encoding="utf-8")
        unique.write_text("other", encoding="utf-8")
        groups = find_duplicate_files([first, second, unique])
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0]["size_bytes"], 4)
        self.assertEqual(len(groups[0]["files"]), 2)

    @unittest.skipIf(
        os.path.normcase("A.txt") == os.path.normcase("a.txt"),
        "the current platform uses case-insensitive path identity",
    )
    def test_posix_case_distinct_paths_can_share_a_manifest(self):
        upper = self.root / "A.txt"
        lower = self.root / "a.txt"
        upper.write_text("same", encoding="utf-8")
        lower.write_text("same", encoding="utf-8")

        manifest = create_integrity_manifest([upper, lower], self.root)
        self.assertEqual({entry["path"] for entry in manifest["files"]}, {"A.txt", "a.txt"})
        groups = find_duplicate_files([upper, lower])
        self.assertEqual(len(groups), 1)
        self.assertEqual(len(groups[0]["files"]), 2)


if __name__ == "__main__":
    unittest.main()
