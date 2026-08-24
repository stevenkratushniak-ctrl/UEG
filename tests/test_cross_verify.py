"""Cross-implementation checks.

The Go implementation writes the evidence; the Python verifier reads it. These
tests build real bundles with the compiled binary and then verify them with the
independent verifier, including the tampered cases. If the two implementations
ever disagree about what a bundle means, these fail.
"""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from verifier.reality_verify import verify_bundle  # noqa: E402

GO = shutil.which("go") or "/usr/local/go/bin/go"
BINARY = REPO / "build" / "ueg"


def build_binary() -> Path:
    BINARY.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run([GO, "build", "-o", str(BINARY), "./cmd/ueg"], cwd=REPO, check=True)
    return BINARY


def read_members(path: Path) -> dict[str, bytes]:
    with tarfile.open(path, "r:gz") as tf:
        return {ti.name: tf.extractfile(ti).read() for ti in tf.getmembers() if ti.isfile()}


def write_members(path: Path, members: dict[str, bytes]) -> None:
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as tf:
        for name in sorted(members):
            ti = tarfile.TarInfo(name)
            ti.size = len(members[name])
            ti.mtime = 0
            ti.mode = 0o644
            tf.addfile(ti, io.BytesIO(members[name]))
    path.write_bytes(gzip.compress(raw.getvalue()))


@unittest.skipUnless(shutil.which(GO) or Path(GO).exists(), "go toolchain not available")
class CrossVerificationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.binary = build_binary()
        cls._helper_tmp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls._helper_tmp.cleanup)
        suffix = ".exe" if os.name == "nt" else ""
        cls.echo_helper = Path(cls._helper_tmp.name) / f"echo{suffix}"
        src = Path(cls._helper_tmp.name) / "echo.go"
        src.write_text(
            """package main

import (
	"fmt"
	"os"
	"strings"
)

func main() {
	fmt.Println(strings.Join(os.Args[1:], " "))
}
""",
            encoding="utf-8",
        )
        subprocess.run([GO, "build", "-o", str(cls.echo_helper), str(src)], check=True)

        cls.legacy_helper = Path(cls._helper_tmp.name) / f"legacy-bundle{suffix}"
        legacy_source = REPO / "build" / "legacy_fixture_helper.go"
        legacy_source.parent.mkdir(parents=True, exist_ok=True)
        legacy_source.write_text(
            """package main

import (
	"os"

	"github.com/stevenkratushniak-ctrl/ueg/internal/bundle"
	"github.com/stevenkratushniak-ctrl/ueg/internal/ledger"
)

func main() {
	l, err := ledger.Open(os.Args[1])
	if err != nil { panic(err) }
	_, err = l.Append(
		ledger.Petition{"action": "legacy-qualification", "target": "synthetic"},
		ledger.PetitionSummary{Surface: "qualification", Action: "legacy-qualification", Target: "synthetic"},
		"ueg:test", "ADMITTED", "SILENT",
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		[]string{"qualification"},
	)
	if err != nil { panic(err) }
	if err := bundle.Build(l, os.Args[2]); err != nil { panic(err) }
}
""",
            encoding="utf-8",
        )
        cls.addClassCleanup(legacy_source.unlink, missing_ok=True)
        subprocess.run(
            [GO, "build", "-o", str(cls.legacy_helper), str(legacy_source)], cwd=REPO, check=True
        )

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.home = Path(self._tmp.name)
        self.env = dict(os.environ, UEG_HOME=str(self.home / "evidence"))

    def ueg(self, *args: str, input_text: str | None = None) -> subprocess.CompletedProcess:
        return subprocess.run(
            [str(self.binary), *args], cwd=self.home, env=self.env, capture_output=True, text=True,
            input=input_text,
        )

    def make_bundle(self) -> Path:
        offline = self.home / "offline"
        offline.mkdir()
        recovery = offline / "recovery.json"
        initialized = self.ueg(
            "identity",
            "init",
            "--home",
            self.env["UEG_HOME"],
            "--recovery-package",
            str(recovery),
            "--label",
            "Cross verifier identity",
            "--passphrase-stdin",
            "--json",
            input_text="test-only cross verifier passphrase\n",
        )
        self.assertEqual(initialized.returncode, 0, initialized.stdout + initialized.stderr)
        self.identity_id = json.loads(initialized.stdout)["identity_id"]
        self.assertEqual(self.ueg("run", "--", str(self.echo_helper), "hello").returncode, 0)
        before_refusal = tree_manifest(Path(self.env["UEG_HOME"]))
        self.assertEqual(self.ueg("run", "--", "rm", "-rf", "/").returncode, 77)
        self.assertEqual(before_refusal, tree_manifest(Path(self.env["UEG_HOME"])))
        self.checkpoint = self.home / "checkpoint.json"
        checkpoint_result = self.ueg(
            "identity",
            "checkpoint",
            "export",
            "--home",
            self.env["UEG_HOME"],
            "--output",
            str(self.checkpoint),
            "--json",
        )
        self.assertEqual(
            checkpoint_result.returncode, 0, checkpoint_result.stdout + checkpoint_result.stderr
        )
        out = self.home / "evidence.tar.gz"
        res = self.ueg("export", str(out))
        self.assertEqual(res.returncode, 0, res.stderr)
        return out

    def test_go_bundle_is_valid_to_the_python_verifier(self) -> None:
        result = verify_bundle(self.make_bundle())
        self.assertTrue(result.ok, result.reason)
        self.assertEqual(result.overall_trust, "TRUST_INDETERMINATE")

    def test_go_and_python_agree_on_a_good_bundle(self) -> None:
        path = self.make_bundle()
        go_result = self.ueg(
            "verify",
            "--json",
            "--expected-identity-id",
            self.identity_id,
            "--checkpoint",
            str(self.checkpoint),
            str(path),
        )
        self.assertEqual(go_result.returncode, 0, go_result.stdout + go_result.stderr)
        python_result = verify_bundle(
            path, expected_identity_id=self.identity_id, checkpoint=self.checkpoint
        )
        self.assertTrue(python_result.ok, python_result.reason)
        self.assertEqual(json.loads(go_result.stdout)["OVERALL_TRUST"], python_result.overall_trust)
        self.assertEqual(json.loads(go_result.stdout)["reason_code"], python_result.reason_code)

    def test_go_and_python_classify_unsafe_archive_as_invalid(self) -> None:
        path = self.make_bundle()
        unsafe = self.home / "unsafe.tar.gz"
        with tarfile.open(path, "r:gz") as source, tarfile.open(unsafe, "w:gz") as target:
            for member in source.getmembers():
                data = source.extractfile(member).read() if member.isfile() else b""
                clone = tarfile.TarInfo(member.name)
                clone.size = len(data)
                clone.mode = member.mode
                target.addfile(clone, io.BytesIO(data))
            escape = tarfile.TarInfo("../escape.txt")
            escape.size = len(b"synthetic")
            target.addfile(escape, io.BytesIO(b"synthetic"))

        go_result = self.ueg("verify", "--json", str(unsafe))
        self.assertEqual(go_result.returncode, 2)
        go_payload = json.loads(go_result.stdout)
        python_result = verify_bundle(unsafe)
        self.assertFalse(python_result.ok)
        self.assertEqual(go_payload["OVERALL_TRUST"], "INVALID")
        self.assertEqual(go_payload["OVERALL_TRUST"], python_result.overall_trust)
        self.assertEqual(go_payload["reason_code"], "EVIDENCE_INVALID")
        self.assertEqual(go_payload["reason_code"], python_result.reason_code)

    def test_identity_trust_requires_the_same_external_genesis_pin(self) -> None:
        path = self.make_bundle()
        members = read_members(path)
        manifest = json.loads(members["MANIFEST.json"])
        self.assertEqual(manifest["version"], "bplus-v1")
        self.assertEqual(manifest["identity_id"], self.identity_id)

        internal = verify_bundle(path)
        self.assertTrue(internal.ok, internal.reason)
        self.assertEqual(internal.overall_trust, "TRUST_INDETERMINATE")

        python_trusted = verify_bundle(
            path, expected_identity_id=self.identity_id, checkpoint=self.checkpoint
        )
        self.assertTrue(python_trusted.ok, python_trusted.reason)
        self.assertEqual(python_trusted.overall_trust, "VERIFIED")

        go_trusted = self.ueg(
            "verify",
            "--json",
            "--expected-identity-id",
            self.identity_id,
            "--checkpoint",
            str(self.checkpoint),
            str(path),
        )
        self.assertEqual(go_trusted.returncode, 0, go_trusted.stdout + go_trusted.stderr)
        self.assertEqual(json.loads(go_trusted.stdout)["OVERALL_TRUST"], "VERIFIED")

        wrong = "ueg:identity:sha256:" + "0" * 64
        python_mismatch = verify_bundle(
            path, expected_identity_id=wrong, checkpoint=self.checkpoint
        )
        self.assertFalse(python_mismatch.ok)
        go_mismatch = self.ueg(
            "verify", "--json", "--expected-identity-id", wrong, str(path)
        )
        self.assertEqual(go_mismatch.returncode, 2)
        go_mismatch_payload = json.loads(go_mismatch.stdout)
        self.assertEqual(go_mismatch_payload["OVERALL_TRUST"], "NOT_TRUSTED")
        self.assertEqual(go_mismatch_payload["reason_code"], python_mismatch.reason_code)
        self.assertEqual(go_mismatch_payload["receipt_count"], 2)

    def test_edited_receipt_is_rejected_by_both(self) -> None:
        path = self.make_bundle()
        members = read_members(path)
        members["receipts.ndjson"] = members["receipts.ndjson"].replace(
            b'"admission_outcome":"ADMITTED"', b'"admission_outcome":"REFUSED"', 1
        )
        tampered = self.home / "tampered.tar.gz"
        write_members(tampered, members)

        self.assertFalse(verify_bundle(tampered).ok)
        self.assertEqual(self.ueg("verify", str(tampered)).returncode, 2)

    def test_refusal_is_inert_and_does_not_enter_the_bundle(self) -> None:
        path = self.make_bundle()
        members = read_members(path)
        receipts = [json.loads(line) for line in members["receipts.ndjson"].splitlines() if line.strip()]
        refusals = [r for r in receipts if r["admission_outcome"] == "REFUSED"]
        self.assertEqual(refusals, [])
        self.assertTrue(verify_bundle(path).ok)

    def test_bundle_carries_no_private_key(self) -> None:
        for name, data in read_members(self.make_bundle()).items():
            self.assertNotIn(b"PRIVATE KEY", data, f"{name} holds private key material")

    def test_generated_bplus_artifacts_match_published_schemas(self) -> None:
        bundle = self.make_bundle()
        members = read_members(bundle)
        schema_dir = REPO / "contract" / "schemas"
        schemas = {
            path.name: json.loads(path.read_text(encoding="utf-8"))
            for path in schema_dir.glob("*.schema.json")
        }
        registry = Registry().with_resources(
            (schema["$id"], Resource.from_contents(schema)) for schema in schemas.values()
        )

        def validate(schema_name: str, value: object) -> None:
            Draft202012Validator(schemas[schema_name], registry=registry).validate(value)

        validate(
            "identity_home.v1.schema.json",
            json.loads((Path(self.env["UEG_HOME"]) / ".ueg-bplus.json").read_text(encoding="utf-8")),
        )
        validate(
            "recovery_package.v1.schema.json",
            json.loads((self.home / "offline" / "recovery.json").read_text(encoding="utf-8")),
        )
        validate("identity_genesis.v1.schema.json", json.loads(members["identity/genesis.json"]))
        validate("identity_card.v1.schema.json", json.loads(members["identity/card.json"]))
        validate("evidence_anchor.v1.schema.json", json.loads(members["identity/evidence_anchor.json"]))
        validate("lifecycle_checkpoint.v1.schema.json", json.loads(members["identity/checkpoint.json"]))
        for line in members["identity/lifecycle.ndjson"].splitlines():
            if line.strip():
                validate("identity_lifecycle_record.v1.schema.json", json.loads(line))

    def test_new_verifiers_preserve_legacy_v2_identity_pinning(self) -> None:
        legacy_home = self.home / "legacy-home"
        legacy_bundle = self.home / "legacy-v2.tar.gz"
        subprocess.run(
            [str(self.legacy_helper), str(legacy_home), str(legacy_bundle)], check=True
        )
        members = read_members(legacy_bundle)
        manifest = json.loads(members["MANIFEST.json"])
        self.assertEqual(manifest["version"], "v2")
        key_id = next(iter(json.loads(members["trust_roots.json"])["ed25519_public_keys"]))
        python_result = verify_bundle(legacy_bundle, expected_key_id=key_id)
        self.assertTrue(python_result.ok, python_result.reason)
        self.assertEqual(python_result.trust_verdict, "IDENTITY_TRUSTED")
        go_result = self.ueg(
            "verify", "--json", "--expected-key-id", key_id, str(legacy_bundle)
        )
        self.assertEqual(go_result.returncode, 0, go_result.stdout + go_result.stderr)
        self.assertEqual(json.loads(go_result.stdout)["trust_verdict"], "IDENTITY_TRUSTED")

    def test_go_and_python_agree_on_root_bound_revocation_anchor_semantics(self) -> None:
        bundle = self.make_bundle()
        anchor = self.home / "known-good-anchor.json"
        anchor_result = self.ueg(
            "identity",
            "anchor",
            "--home",
            self.env["UEG_HOME"],
            "--output",
            str(anchor),
            "--json",
        )
        self.assertEqual(anchor_result.returncode, 0, anchor_result.stdout + anchor_result.stderr)
        status = self.ueg("identity", "status", "--home", self.env["UEG_HOME"], "--json")
        key_id = json.loads(status.stdout)["active_operational_key_id"]
        recovery = self.home / "offline" / "recovery.json"
        revoked = self.ueg(
            "identity",
            "revoke",
            "--home",
            self.env["UEG_HOME"],
            "--recovery-package",
            str(recovery),
            "--reason",
            "QUALIFIED_COMPROMISE",
            "--anchor",
            str(anchor),
            "--confirm-key-id",
            key_id,
            "--confirm-compromise",
            "--passphrase-stdin",
            "--json",
            input_text="test-only cross verifier passphrase\n",
        )
        self.assertEqual(revoked.returncode, 0, revoked.stdout + revoked.stderr)
        revoked_checkpoint = self.home / "revoked-checkpoint.json"
        exported = self.ueg(
            "identity",
            "checkpoint",
            "export",
            "--home",
            self.env["UEG_HOME"],
            "--output",
            str(revoked_checkpoint),
            "--json",
        )
        self.assertEqual(exported.returncode, 0, exported.stdout + exported.stderr)

        for supplied_anchor, expected_overall, expected_reason in (
            (None, "TRUST_INDETERMINATE", "EPOCH_TRUST_INDETERMINATE"),
            (anchor, "VERIFIED", "BPLUS_VERIFIED_AT_CHECKPOINT"),
        ):
            go_args = [
                "verify",
                "--json",
                "--expected-identity-id",
                self.identity_id,
                "--checkpoint",
                str(revoked_checkpoint),
            ]
            if supplied_anchor is not None:
                go_args.extend(["--anchor", str(supplied_anchor)])
            go_args.append(str(bundle))
            go_result = self.ueg(*go_args)
            python_result = verify_bundle(
                bundle,
                expected_identity_id=self.identity_id,
                checkpoint=revoked_checkpoint,
                anchor=supplied_anchor,
            )
            go_payload = json.loads(go_result.stdout)
            self.assertEqual(go_payload["OVERALL_TRUST"], expected_overall)
            self.assertEqual(python_result.overall_trust, expected_overall)
            self.assertEqual(go_payload["reason_code"], expected_reason)
            self.assertEqual(python_result.reason_code, expected_reason)


def tree_manifest(root: Path) -> tuple[tuple[str, str], ...]:
    return tuple(
        sorted(
            (path.relative_to(root).as_posix(), hashlib.sha256(path.read_bytes()).hexdigest())
            for path in root.rglob("*")
            if path.is_file()
        )
    )


if __name__ == "__main__":
    unittest.main()
