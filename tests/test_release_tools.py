from __future__ import annotations

import hashlib
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
import zipfile


REPO = Path(__file__).resolve().parents[1]
TOOLS = REPO / "tools"
QUALIFICATION = REPO / "qualification"
sys.path.insert(0, str(TOOLS))
sys.path.insert(0, str(QUALIFICATION))

import build_release  # noqa: E402
import generate_sbom  # noqa: E402
import native_release_walkthrough  # noqa: E402
import package_python_verifier  # noqa: E402
import verify_release  # noqa: E402


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class ReleaseToolTests(unittest.TestCase):
    def test_zip_and_tar_archives_are_deterministic(self) -> None:
        members = [
            ("README.md", b"read me\n", 0o644),
            ("ueg", b"binary bytes", 0o755),
        ]
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            first_zip = root / "first.zip"
            second_zip = root / "second.zip"
            first_tar = root / "first.tar.gz"
            second_tar = root / "second.tar.gz"
            build_release.build_zip(first_zip, "ueg-test", members)
            build_release.build_zip(second_zip, "ueg-test", members)
            build_release.build_tar(first_tar, "ueg-test", members)
            build_release.build_tar(second_tar, "ueg-test", members)
            self.assertEqual(digest(first_zip), digest(second_zip))
            self.assertEqual(digest(first_tar), digest(second_tar))

            with zipfile.ZipFile(first_zip) as archive:
                self.assertEqual(
                    archive.getinfo("ueg-test/README.md").date_time,
                    package_python_verifier.FIXED_TIME,
                )
                self.assertEqual(
                    archive.getinfo("ueg-test/ueg").external_attr >> 16,
                    0o100755,
                )
            with tarfile.open(first_tar, mode="r:gz") as archive:
                member = archive.getmember("ueg-test/ueg")
                self.assertEqual(member.mtime, 0)
                self.assertEqual(member.mode, 0o755)

    def test_python_verifier_package_has_release_notices(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            output = Path(raw) / "verifier.zip"
            package_python_verifier.package(REPO, output)
            with zipfile.ZipFile(output) as archive:
                names = set(archive.namelist())
                self.assertIn("LICENSE", names)
                self.assertIn("THIRD_PARTY_NOTICES.md", names)
                self.assertIn("requirements.lock", names)
                self.assertIn("verifier/reality_verify.py", names)

    def test_native_packages_include_bplus_demos(self) -> None:
        self.assertEqual(
            set(build_release.PACKAGE_DEMOS),
            {"demo/demo.sh", "demo/demo.ps1"},
        )
        self.assertTrue({"demo.sh", "demo.ps1", "DEMO_TRANSCRIPT.txt"} <= verify_release.PACKAGE_DOCS)

        powershell_demo = (REPO / "demo" / "demo.ps1").read_text(encoding="utf-8")
        bash_demo = (REPO / "demo" / "demo.sh").read_text(encoding="utf-8")
        self.assertIn("..\\ueg.exe", powershell_demo)
        self.assertIn('$SCRIPT_DIR/../ueg', bash_demo)
        self.assertIn("UEG_PYTHON_VERIFIER_ROOT", bash_demo)

    def test_sbom_covers_every_locked_python_dependency(self) -> None:
        document = generate_sbom.generate(REPO, "test-version")
        packages = {(item["name"], item["versionInfo"]) for item in document["packages"]}
        for name, version in generate_sbom.python_requirements(REPO):
            self.assertIn((name, version), packages)
        self.assertIn(("golang.org/x/sys", "v0.30.0"), packages)
        self.assertIn(("golang.org/x/crypto", "v0.33.0"), packages)
        self.assertIn(("golang.org/x/term", "v0.29.0"), packages)
        for item in document["packages"]:
            if item["name"].startswith("golang.org/x/"):
                self.assertEqual(item["licenseDeclared"], "BSD-3-Clause")
        self.assertEqual(document["spdxVersion"], "SPDX-2.3")

    def test_checksum_parser_rejects_duplicate_and_malformed_lines(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            sums = Path(raw) / "SHA256SUMS"
            checksum = "a" * 64
            sums.write_text(f"{checksum}  artifact\n{checksum}  artifact\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "duplicate"):
                verify_release.read_sums(sums)
            sums.write_text("not-a-checksum\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "malformed"):
                verify_release.read_sums(sums)

    def test_private_key_detection_does_not_flag_verifier_source_literal(self) -> None:
        source = b'PRIVATE_KEY_PEM = b"-----BEGIN PRIVATE KEY-----"\n'
        key = b"-----BEGIN PRIVATE KEY-----\nsynthetic\n-----END PRIVATE KEY-----\n"
        self.assertFalse(verify_release.contains_private_key(source))
        self.assertTrue(verify_release.contains_private_key(key))

    def test_archive_reader_rejects_alias_duplicates_and_non_files(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            duplicate = root / "duplicate.zip"
            with zipfile.ZipFile(duplicate, "w") as archive:
                archive.writestr("root/File.txt", b"first")
                archive.writestr("root/file.txt", b"second")
            with self.assertRaisesRegex(ValueError, "duplicate member"):
                verify_release.archive_members(duplicate)

            linked = root / "linked.tar.gz"
            with tarfile.open(linked, mode="w:gz") as archive:
                member = tarfile.TarInfo("root/link")
                member.type = tarfile.SYMTYPE
                member.linkname = "../outside"
                archive.addfile(member)
            with self.assertRaisesRegex(ValueError, "non-file member"):
                verify_release.archive_members(linked)

    def test_expected_release_artifacts_are_exact_and_version_safe(self) -> None:
        artifacts = verify_release.expected_artifacts("2.0.0-rc.1")
        self.assertEqual(len(artifacts), 14)
        self.assertIn("ueg-2.0.0-rc.1-windows-amd64.zip", artifacts)
        self.assertIn("ueg-2.0.0-rc.1-source.tar.gz", artifacts)
        with self.assertRaisesRegex(ValueError, "unsafe release version"):
            verify_release.expected_artifacts("../../release")

    def test_native_refusal_probe_is_disposable_and_non_executable(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            command = native_release_walkthrough.harmless_prohibited_probe(Path(raw))
            self.assertEqual(Path(command[0]).stem.lower(), "format")
            self.assertEqual(command[1], "synthetic-target")
            self.assertFalse(Path(command[0]).exists())


if __name__ == "__main__":
    unittest.main()
