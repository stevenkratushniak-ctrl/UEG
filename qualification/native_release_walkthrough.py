from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import zipfile


def sha256(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def manifest(root: Path) -> list[dict[str, object]]:
    if not root.exists():
        return []
    return [
        {
            "path": path.relative_to(root).as_posix(),
            "bytes": path.stat().st_size,
            "sha256": sha256(path),
        }
        for path in sorted(root.rglob("*"))
        if path.is_file()
    ]


def write_json(path: Path, value: object) -> None:
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )


REQUIRED_PACKAGE_FILES = {
    "README.md",
    "INSTALL.md",
    "LIMITS.md",
    "PROVENANCE.md",
    "DEMO_TRANSCRIPT.txt",
    "demo.sh",
    "demo.ps1",
    "LICENSE",
    "UEG.spdx.json",
}


def harmless_prohibited_probe(workspace: Path) -> list[str]:
    # The basename is unconditionally PROHIBITED by UEG policy, but the target
    # intentionally does not exist. If admission regresses, process creation
    # fails harmlessly inside the disposable workspace instead of invoking a
    # destructive operating-system utility.
    name = "format.exe" if os.name == "nt" else "format"
    return [str(workspace / "intentionally-missing" / name), "synthetic-target"]


def safe_destination(root: Path, name: str) -> Path:
    normalized = name.replace("\\", "/")
    if normalized.startswith("/") or "/../" in f"/{normalized}/":
        raise ValueError(f"unsafe archive member: {name}")
    destination = (root / normalized).resolve()
    if root.resolve() not in destination.parents and destination != root.resolve():
        raise ValueError(f"archive member escapes extraction root: {name}")
    return destination


def prepare_binary(artifact: Path) -> tuple[Path, Path | None, str]:
    extraction: Path | None = None
    kind = "raw-binary"
    if artifact.suffix == ".zip":
        kind = "zip"
        extraction = Path(tempfile.mkdtemp(prefix="ueg-native-acquisition-"))
        with zipfile.ZipFile(artifact) as archive:
            names = archive.namelist()
            if len(names) != len(set(names)):
                raise ValueError("release archive has duplicate members")
            for info in archive.infolist():
                if info.is_dir():
                    continue
                destination = safe_destination(extraction, info.filename)
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(archive.read(info))
                mode = (info.external_attr >> 16) & 0o777
                if mode:
                    destination.chmod(mode)
    elif artifact.name.endswith(".tar.gz"):
        kind = "tar.gz"
        extraction = Path(tempfile.mkdtemp(prefix="ueg-native-acquisition-"))
        with tarfile.open(artifact, mode="r:gz") as archive:
            members = archive.getmembers()
            names = [member.name for member in members]
            if len(names) != len(set(names)):
                raise ValueError("release archive has duplicate members")
            for member in members:
                if member.isdir():
                    continue
                if not member.isfile():
                    raise ValueError(f"release archive has non-file member: {member.name}")
                destination = safe_destination(extraction, member.name)
                destination.parent.mkdir(parents=True, exist_ok=True)
                source = archive.extractfile(member)
                if source is None:
                    raise ValueError(f"cannot read archive member: {member.name}")
                destination.write_bytes(source.read())
                destination.chmod(member.mode & 0o777)
    if extraction is None:
        return artifact, None, kind

    package_files = {path.name for path in extraction.rglob("*") if path.is_file()}
    missing = REQUIRED_PACKAGE_FILES - package_files
    if missing:
        raise ValueError(f"release archive is missing package files: {sorted(missing)}")
    executable_name = "ueg.exe" if os.name == "nt" else "ueg"
    binaries = [path for path in extraction.rglob(executable_name) if path.is_file()]
    if len(binaries) != 1:
        raise ValueError(f"release archive must contain exactly one {executable_name}")
    return binaries[0], extraction, kind


class Walkthrough:
    def __init__(self, binary: Path, output: Path, artifact_sha256: str, artifact_kind: str) -> None:
        self.binary = binary
        self.output = output
        self.logs = output / "logs"
        self.manifests = output / "manifests"
        self.artifacts = output / "artifacts"
        # Keep runtime state on the platform's native temporary filesystem.
        # Mounted/shared folders can intentionally fail UEG's key-permission
        # checks and are not a valid substitute for a native home.
        self.workspace = Path(tempfile.mkdtemp(prefix="ueg-native-walkthrough-"))
        self.home = self.workspace / "evidence"
        self.install = self.workspace / ("ueg.exe" if os.name == "nt" else "ueg")
        self.commands: list[dict[str, object]] = []
        self.failures: list[str] = []
        self.artifact_sha256 = artifact_sha256
        self.artifact_kind = artifact_kind
        self.migration_result: dict[str, object] | None = None

    def run(
        self,
        name: str,
        args: list[str],
        *,
        expected: set[int],
        env: dict[str, str] | None = None,
        executable: Path | None = None,
        input_bytes: bytes | None = None,
    ) -> subprocess.CompletedProcess[bytes]:
        command = [str(executable or self.install), *args]
        result = subprocess.run(
            command,
            cwd=self.workspace,
            env=env,
            check=False,
            stdin=None if input_bytes is not None else subprocess.DEVNULL,
            input=input_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        (self.logs / f"{name}.stdout.log").write_bytes(result.stdout)
        (self.logs / f"{name}.stderr.log").write_bytes(result.stderr)
        record = {"name": name, "arguments": args, "exit_code": result.returncode}
        self.commands.append(record)
        if result.returncode not in expected:
            self.failures.append(
                f"{name}: exit {result.returncode}, expected one of {sorted(expected)}"
            )
        return result

    def execute(self, python_verifier: Path | None, legacy_binary: Path | None) -> dict[str, object]:
        self.logs.mkdir(parents=True)
        self.manifests.mkdir()
        self.artifacts.mkdir()
        shutil.copyfile(self.binary, self.install)
        self.install.chmod(self.install.stat().st_mode | stat.S_IXUSR)

        inert_env = os.environ.copy()
        inert_env["UEG_HOME"] = str(self.home)
        before_inert = manifest(self.workspace)
        write_json(self.manifests / "inert_before.json", before_inert)
        self.run("help", ["--help"], expected={0}, env=inert_env)
        self.run("help_run", ["help", "run"], expected={0}, env=inert_env)
        self.run("version", ["version"], expected={0}, env=inert_env)
        self.run("no_arguments", [], expected={0}, env=inert_env)
        self.run("unknown_command", ["rnu"], expected={1}, env=inert_env)
        self.run("unknown_option", ["run", "--wat"], expected={1}, env=inert_env)
        self.run("missing_verify", ["verify", "missing.tar.gz"], expected={2}, env=inert_env)
        after_inert = manifest(self.workspace)
        write_json(self.manifests / "inert_after.json", after_inert)
        # Command logs live outside the workspace manifest. The installed binary
        # is present in both snapshots; no evidence home may appear.
        if before_inert != after_inert or self.home.exists():
            self.failures.append("information/error paths changed the disposable workspace")

        offline = self.workspace / "offline"
        offline.mkdir()
        recovery = offline / "recovery.json"
        passphrase = b"native qualification recovery passphrase\n"
        initialized = self.run(
            "identity_init",
            [
                "identity", "init", "--home", str(self.home),
                "--recovery-package", str(recovery), "--label", "Native qualification",
                "--passphrase-stdin", "--json",
            ],
            expected={0},
            input_bytes=passphrase,
        )
        try:
            initialized_payload = json.loads(initialized.stdout)
            identity_id = initialized_payload["identity_id"]
            key_id = initialized_payload["operational_key_id"]
        except Exception as error:
            identity_id = ""
            key_id = ""
            self.failures.append(f"identity initialization returned invalid JSON: {error}")
        if not self.home.is_dir() or not recovery.is_file():
            self.failures.append("explicit initialization did not create both selected destinations")
        self.run(
            "recovery_package_verify",
            [
                "identity", "recovery-verify", "--recovery-package", str(recovery),
                "--identity-id", identity_id, "--passphrase-stdin", "--json",
            ],
            expected={0},
            input_bytes=passphrase,
        )

        before_check = manifest(self.home)
        checked = self.run(
            "inert_check",
            ["check", "--json", "--home", str(self.home), "--", "whoami"],
            expected={0},
        )
        if manifest(self.home) != before_check:
            self.failures.append("check changed the initialized evidence home")
        try:
            if json.loads(checked.stdout).get("state_changed") is not False:
                self.failures.append("check did not report its inert state truthfully")
        except Exception as error:
            self.failures.append(f"check returned invalid JSON: {error}")

        self.run(
            "normal_run",
            ["run", "--json", "--home", str(self.home), "--", "whoami"],
            expected={0},
        )
        prohibited_probe = harmless_prohibited_probe(self.workspace)
        before_refusal = manifest(self.home)
        refused = self.run(
            "prohibited_refusal",
            ["run", "--json", "--home", str(self.home), "--", *prohibited_probe],
            expected={77},
        )
        if Path(prohibited_probe[0]).exists():
            self.failures.append("qualification created its intentionally missing refusal probe")
        if manifest(self.home) != before_refusal:
            self.failures.append("policy refusal changed the evidence home")
        try:
            refusal_payload = json.loads(refused.stdout)
            if refusal_payload.get("executed") or refusal_payload.get("decision") != "REFUSED":
                self.failures.append("prohibited command was not a truthful non-executed refusal")
        except Exception as error:
            self.failures.append(f"refusal returned invalid JSON: {error}")

        self.run(
            "restart_identity_status",
            ["identity", "status", "--json", "--home", str(self.home)],
            expected={0},
        )
        self.run(
            "restart_ledger",
            ["ledger", "--json", "--home", str(self.home)],
            expected={0},
        )
        transfer = self.workspace / "transfer"
        transfer.mkdir()
        card = transfer / "identity-card.json"
        anchor = transfer / "known-good-anchor.json"
        checkpoint = transfer / "checkpoint.json"
        self.run("identity_card", ["identity", "card", "--home", str(self.home), "--output", str(card), "--json"], expected={0})
        self.run("evidence_anchor", ["identity", "anchor", "--home", str(self.home), "--output", str(anchor), "--json"], expected={0})
        self.run("checkpoint_export", ["identity", "checkpoint", "export", "--home", str(self.home), "--output", str(checkpoint), "--json"], expected={0})
        bundle = transfer / "evidence.tar.gz"
        self.run(
            "export",
            ["export", "--json", "--home", str(self.home), str(bundle)],
            expected={0},
        )
        moved = self.workspace / "moved-evidence.tar.gz"
        if not bundle.is_file():
            self.failures.append("export did not produce the requested bundle")
        else:
            self.run("verify_go_unpinned", ["verify", "--json", str(bundle)], expected={2})
            if identity_id:
                self.run(
                    "verify_go_pinned",
                    ["verify", "--expected-identity-id", identity_id, "--checkpoint", str(checkpoint), str(bundle)],
                    expected={0},
                )
            shutil.copyfile(bundle, moved)
            shutil.copyfile(bundle, self.artifacts / "synthetic-evidence.tar.gz")
            shutil.copyfile(checkpoint, self.artifacts / "checkpoint.json")
            shutil.copyfile(card, self.artifacts / "identity-card.json")
            self.run(
                "verify_moved",
                ["verify", "--expected-identity-id", identity_id, "--checkpoint", str(checkpoint), str(moved)],
                expected={0},
            )

            tampered = self.workspace / "tampered-evidence.tar.gz"
            data = bytearray(bundle.read_bytes())
            if data:
                data[len(data) // 2] ^= 1
            tampered.write_bytes(data)
            self.run("verify_tampered", ["verify", str(tampered)], expected={2})

        transferred = self.run(
            "official_transfer",
            [
                "identity", "transfer", "--home", str(self.home),
                "--recovery-package", str(recovery), "--reason", "NATIVE_TRANSFER",
                "--checkpoint", str(checkpoint), "--passphrase-stdin", "--json",
            ],
            expected={0},
            input_bytes=passphrase,
        )
        try:
            key_id = json.loads(transferred.stdout)["operational_key_id"]
        except Exception as error:
            self.failures.append(f"transfer returned invalid JSON: {error}")
        self.run("post_transfer_run", ["run", "--json", "--home", str(self.home), "--", "whoami"], expected={0})
        post_transfer_checkpoint = transfer / "post-transfer-checkpoint.json"
        self.run("post_transfer_checkpoint", ["identity", "checkpoint", "export", "--home", str(self.home), "--output", str(post_transfer_checkpoint), "--json"], expected={0})
        if bundle.is_file():
            self.run(
                "historical_epoch_verify",
                ["verify", "--expected-identity-id", identity_id, "--checkpoint", str(post_transfer_checkpoint), str(bundle)],
                expected={0},
            )

        self.run(
            "suspend",
            ["identity", "suspend", "--home", str(self.home), "--recovery-package", str(recovery), "--reason", "NATIVE_SUSPEND", "--passphrase-stdin", "--json"],
            expected={0}, input_bytes=passphrase,
        )
        before_suspended_run = manifest(self.home)
        self.run("suspended_run_refusal", ["run", "--json", "--home", str(self.home), "--", "whoami"], expected={1})
        if manifest(self.home) != before_suspended_run:
            self.failures.append("suspended signing attempt changed evidence")
        self.run(
            "resume",
            ["identity", "resume", "--home", str(self.home), "--recovery-package", str(recovery), "--reason", "NATIVE_RESUME", "--passphrase-stdin", "--json"],
            expected={0}, input_bytes=passphrase,
        )
        recovered = self.run(
            "operational_key_recovery",
            ["identity", "recover", "--home", str(self.home), "--recovery-package", str(recovery), "--reason", "NATIVE_RECOVERY", "--passphrase-stdin", "--json"],
            expected={0}, input_bytes=passphrase,
        )
        try:
            key_id = json.loads(recovered.stdout)["operational_key_id"]
        except Exception as error:
            self.failures.append(f"recovery returned invalid JSON: {error}")
        self.run("post_recovery_run", ["run", "--json", "--home", str(self.home), "--", "whoami"], expected={0})
        pre_revoke_anchor = transfer / "pre-revoke-anchor.json"
        pre_revoke_bundle = transfer / "pre-revoke-evidence.tar.gz"
        self.run("pre_revoke_anchor", ["identity", "anchor", "--home", str(self.home), "--output", str(pre_revoke_anchor), "--json"], expected={0})
        self.run("pre_revoke_export", ["export", "--json", "--home", str(self.home), str(pre_revoke_bundle)], expected={0})
        self.run(
            "revoke",
            [
                "identity", "revoke", "--home", str(self.home), "--recovery-package", str(recovery),
                "--reason", "NATIVE_CONFIRMED_COMPROMISE", "--anchor", str(pre_revoke_anchor),
                "--confirm-key-id", key_id, "--confirm-compromise", "--passphrase-stdin", "--json",
            ],
            expected={0}, input_bytes=passphrase,
        )
        revoked_checkpoint = transfer / "revoked-checkpoint.json"
        self.run("revoked_checkpoint", ["identity", "checkpoint", "export", "--home", str(self.home), "--output", str(revoked_checkpoint), "--json"], expected={0})
        self.run(
            "revoked_without_anchor",
            ["verify", "--json", "--expected-identity-id", identity_id, "--checkpoint", str(revoked_checkpoint), str(pre_revoke_bundle)],
            expected={2},
        )
        partial_anchor = self.run(
            "revoked_with_partial_anchor",
            ["verify", "--json", "--expected-identity-id", identity_id, "--checkpoint", str(revoked_checkpoint), "--anchor", str(pre_revoke_anchor), str(pre_revoke_bundle)],
            expected={2},
        )
        try:
            partial_payload = json.loads(partial_anchor.stdout)
            if (
                partial_payload.get("OVERALL_TRUST") != "TRUST_INDETERMINATE"
                or partial_payload.get("reason_code") != "EPOCH_TRUST_INDETERMINATE"
            ):
                self.failures.append("a bundle spanning an earlier unanchored recovered epoch received the wrong trust result")
        except Exception as error:
            self.failures.append(f"partial-anchor verification returned invalid JSON: {error}")
        before_revoked_run = manifest(self.home)
        self.run("revoked_run_refusal", ["run", "--json", "--home", str(self.home), "--", "whoami"], expected={1})
        if manifest(self.home) != before_revoked_run:
            self.failures.append("revoked signing attempt changed evidence")

        # A separate identity proves the positive compromise case without
        # laundering an earlier, independently unanchored lost-key epoch.
        anchored_home = self.workspace / "anchored-revocation-evidence"
        anchored_recovery = offline / "anchored-revocation-recovery.json"
        anchored_passphrase = b"native anchored revocation passphrase\n"
        anchored_init = self.run(
            "anchored_identity_init",
            [
                "identity", "init", "--home", str(anchored_home),
                "--recovery-package", str(anchored_recovery),
                "--label", "Anchored revocation qualification",
                "--passphrase-stdin", "--json",
            ],
            expected={0},
            input_bytes=anchored_passphrase,
        )
        try:
            anchored_payload = json.loads(anchored_init.stdout)
            anchored_identity_id = anchored_payload["identity_id"]
            anchored_key_id = anchored_payload["operational_key_id"]
        except Exception as error:
            anchored_identity_id = ""
            anchored_key_id = ""
            self.failures.append(f"anchored identity initialization returned invalid JSON: {error}")
        self.run(
            "anchored_normal_run",
            ["run", "--json", "--home", str(anchored_home), "--", "whoami"],
            expected={0},
        )
        anchored_anchor = transfer / "anchored-pre-compromise-anchor.json"
        anchored_bundle = transfer / "anchored-pre-compromise-evidence.tar.gz"
        anchored_checkpoint = transfer / "anchored-revoked-checkpoint.json"
        self.run(
            "anchored_pre_compromise_anchor",
            ["identity", "anchor", "--home", str(anchored_home), "--output", str(anchored_anchor), "--json"],
            expected={0},
        )
        self.run(
            "anchored_pre_compromise_export",
            ["export", "--json", "--home", str(anchored_home), str(anchored_bundle)],
            expected={0},
        )
        self.run(
            "anchored_revoke",
            [
                "identity", "revoke", "--home", str(anchored_home),
                "--recovery-package", str(anchored_recovery),
                "--reason", "NATIVE_CONFIRMED_COMPROMISE",
                "--anchor", str(anchored_anchor),
                "--confirm-key-id", anchored_key_id,
                "--confirm-compromise", "--passphrase-stdin", "--json",
            ],
            expected={0},
            input_bytes=anchored_passphrase,
        )
        self.run(
            "anchored_revoked_checkpoint",
            ["identity", "checkpoint", "export", "--home", str(anchored_home), "--output", str(anchored_checkpoint), "--json"],
            expected={0},
        )
        self.run(
            "anchored_revoked_without_anchor",
            ["verify", "--json", "--expected-identity-id", anchored_identity_id, "--checkpoint", str(anchored_checkpoint), str(anchored_bundle)],
            expected={2},
        )
        anchored_verified = self.run(
            "anchored_revoked_at_known_anchor",
            ["verify", "--json", "--expected-identity-id", anchored_identity_id, "--checkpoint", str(anchored_checkpoint), "--anchor", str(anchored_anchor), str(anchored_bundle)],
            expected={0},
        )
        try:
            anchored_verified_payload = json.loads(anchored_verified.stdout)
            if (
                anchored_verified_payload.get("OVERALL_TRUST") != "VERIFIED"
                or anchored_verified_payload.get("reason_code") != "BPLUS_VERIFIED_AT_CHECKPOINT"
            ):
                self.failures.append("independently anchored pre-compromise evidence did not receive VERIFIED")
        except Exception as error:
            self.failures.append(f"anchored verification returned invalid JSON: {error}")
        self.run(
            "anchored_current_status_unavailable",
            [
                "verify", "--json", "--expected-identity-id", anchored_identity_id,
                "--checkpoint", str(anchored_checkpoint), "--anchor", str(anchored_anchor),
                "--require-current-status", str(anchored_bundle),
            ],
            expected={2},
        )
        before_anchored_revoked_run = manifest(anchored_home)
        self.run(
            "anchored_revoked_run_refusal",
            ["run", "--json", "--home", str(anchored_home), "--", "whoami"],
            expected={1},
        )
        if manifest(anchored_home) != before_anchored_revoked_run:
            self.failures.append("anchored revoked signing attempt changed evidence")

        for source, destination_name in (
            (pre_revoke_anchor, "multi-epoch-pre-revoke-anchor.json"),
            (pre_revoke_bundle, "multi-epoch-pre-revoke-evidence.tar.gz"),
            (revoked_checkpoint, "multi-epoch-revoked-checkpoint.json"),
            (anchored_anchor, "anchored-pre-compromise-anchor.json"),
            (anchored_bundle, "anchored-pre-compromise-evidence.tar.gz"),
            (anchored_checkpoint, "anchored-revoked-checkpoint.json"),
        ):
            if source.is_file():
                shutil.copyfile(source, self.artifacts / destination_name)
            else:
                self.failures.append(f"expected public qualification artifact is missing: {source.name}")

        if python_verifier is not None and moved.is_file():
            verifier_root = self.workspace / "python-verifier"
            with zipfile.ZipFile(python_verifier) as archive:
                for name in archive.namelist():
                    normalized = name.replace("\\", "/")
                    if normalized.startswith("/") or "/../" in f"/{normalized}/":
                        raise ValueError(f"unsafe Python verifier member: {name}")
                archive.extractall(verifier_root)
            python_env = os.environ.copy()
            python_env["PYTHONPATH"] = str(verifier_root)
            result = subprocess.run(
                [
                    sys.executable, "-m", "verifier.reality_verify", "--json",
                    "--expected-identity-id", identity_id, "--checkpoint", str(checkpoint), str(moved),
                ],
                cwd=self.workspace,
                env=python_env,
                check=False,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            (self.logs / "verify_python.stdout.log").write_bytes(result.stdout)
            (self.logs / "verify_python.stderr.log").write_bytes(result.stderr)
            self.commands.append(
                {"name": "verify_python", "arguments": ["--expected-identity-id", identity_id, "--checkpoint", "checkpoint.json", "moved-evidence.tar.gz"], "exit_code": result.returncode}
            )
            if result.returncode != 0:
                self.failures.append(f"packaged Python verifier exited {result.returncode}")

            anchored_python = subprocess.run(
                [
                    sys.executable, "-m", "verifier.reality_verify", "--json",
                    "--expected-identity-id", anchored_identity_id,
                    "--checkpoint", str(anchored_checkpoint),
                    "--anchor", str(anchored_anchor),
                    str(anchored_bundle),
                ],
                cwd=self.workspace,
                env=python_env,
                check=False,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            (self.logs / "verify_python_anchored_revocation.stdout.log").write_bytes(anchored_python.stdout)
            (self.logs / "verify_python_anchored_revocation.stderr.log").write_bytes(anchored_python.stderr)
            self.commands.append(
                {
                    "name": "verify_python_anchored_revocation",
                    "arguments": ["--expected-identity-id", anchored_identity_id, "--checkpoint", "anchored-revoked-checkpoint.json", "--anchor", "anchored-pre-compromise-anchor.json", "anchored-pre-compromise-evidence.tar.gz"],
                    "exit_code": anchored_python.returncode,
                }
            )
            if anchored_python.returncode != 0:
                self.failures.append(f"packaged Python anchored-revocation verification exited {anchored_python.returncode}")

        if legacy_binary is not None:
            self.migration_result = self.execute_migration(legacy_binary)

        before_remove = manifest(self.home)
        write_json(self.manifests / "evidence_before_binary_removal.json", before_remove)
        self.install.unlink(missing_ok=True)
        after_binary_remove = manifest(self.home)
        write_json(self.manifests / "evidence_after_binary_removal.json", after_binary_remove)
        if before_remove != after_binary_remove:
            self.failures.append("removing the executable changed retained evidence")
        shutil.rmtree(self.home)
        recovery.unlink(missing_ok=True)
        shutil.rmtree(anchored_home)
        anchored_recovery.unlink(missing_ok=True)
        if self.home.exists():
            self.failures.append("deliberate evidence cleanup did not remove the disposable home")
        if anchored_home.exists():
            self.failures.append("deliberate anchored-identity cleanup did not remove the disposable home")

        return {
            "schema": "ueg.native-release-qualification.v1",
            "platform": sys.platform,
            "machine": platform.machine(),
            "input_artifact_sha256": self.artifact_sha256,
            "input_artifact_kind": self.artifact_kind,
            "binary_sha256": sha256(self.binary),
            "signing_key_id": key_id,
            "identity_id": identity_id,
            "migration": self.migration_result,
            "commands": self.commands,
            "failures": self.failures,
            "passed": not self.failures,
        }

    def execute_migration(self, legacy_binary: Path) -> dict[str, object]:
        legacy_install = self.workspace / ("ueg-v2.exe" if os.name == "nt" else "ueg-v2")
        shutil.copyfile(legacy_binary, legacy_install)
        legacy_install.chmod(legacy_install.stat().st_mode | stat.S_IXUSR)
        legacy_home = self.workspace / "legacy-evidence"
        migration_public = self.workspace / "migration-public"
        migration_public.mkdir()
        migration_recovery = self.workspace / "offline" / "migration-recovery.json"
        migration_passphrase = b"native migration recovery passphrase\n"

        legacy_run = self.run(
            "migration_legacy_run",
            ["run", "--json", "--home", str(legacy_home), "--", "whoami"],
            expected={0},
            executable=legacy_install,
        )
        try:
            legacy_payload = json.loads(legacy_run.stdout)
            legacy_key_id = legacy_payload["signing_key_id"]
        except Exception as error:
            legacy_key_id = ""
            self.failures.append(f"legacy migration fixture returned invalid JSON: {error}")
        legacy_bundle = migration_public / "legacy-before-migration.tar.gz"
        self.run(
            "migration_legacy_export",
            ["export", "--json", "--home", str(legacy_home), str(legacy_bundle)],
            expected={0},
            executable=legacy_install,
        )
        self.run(
            "migration_bplus_verifies_legacy",
            ["verify", "--json", "--expected-key-id", legacy_key_id, str(legacy_bundle)],
            expected={0},
        )
        migrated = self.run(
            "migration_enroll",
            [
                "identity", "migrate", "--home", str(legacy_home),
                "--recovery-package", str(migration_recovery),
                "--confirm-key-id", legacy_key_id,
                "--confirm-not-compromised", "--label", "Migrated qualification ledger",
                "--passphrase-stdin", "--json",
            ],
            expected={0},
            input_bytes=migration_passphrase,
        )
        try:
            migration_payload = json.loads(migrated.stdout)
            identity_id = migration_payload["identity_id"]
        except Exception as error:
            identity_id = ""
            self.failures.append(f"migration returned invalid JSON: {error}")

        before_downgrade = manifest(legacy_home)
        write_json(self.manifests / "migration_before_frozen_v2_attempt.json", before_downgrade)
        sentinel = self.workspace / "frozen-v2-downgrade-executed.txt"
        sentinel_code = f"from pathlib import Path; Path({str(sentinel)!r}).write_text('executed', encoding='utf-8')"
        frozen_attempt = self.run(
            "migration_frozen_v2_downgrade_refusal",
            [
                "run", "--json", "--allow-unclassified", "--home", str(legacy_home),
                "--", sys.executable, "-c", sentinel_code,
            ],
            expected={1, 2},
            executable=legacy_install,
        )
        after_downgrade = manifest(legacy_home)
        write_json(self.manifests / "migration_after_frozen_v2_attempt.json", after_downgrade)
        if sentinel.exists():
            self.failures.append("frozen v2 executed a command after B+ migration")
        if before_downgrade != after_downgrade:
            self.failures.append("frozen v2 changed the migrated B+ evidence home")
        if frozen_attempt.returncode == 0:
            self.failures.append("frozen v2 did not fail closed on the migrated home")

        self.run(
            "migration_bplus_continues",
            ["run", "--json", "--home", str(legacy_home), "--", "whoami"],
            expected={0},
        )
        checkpoint = migration_public / "migration-checkpoint.json"
        bplus_bundle = migration_public / "bplus-after-migration.tar.gz"
        self.run(
            "migration_checkpoint",
            ["identity", "checkpoint", "export", "--home", str(legacy_home), "--output", str(checkpoint), "--json"],
            expected={0},
        )
        self.run(
            "migration_bplus_export",
            ["export", "--json", "--home", str(legacy_home), str(bplus_bundle)],
            expected={0},
        )
        self.run(
            "migration_bplus_verify",
            ["verify", "--json", "--expected-identity-id", identity_id, "--checkpoint", str(checkpoint), str(bplus_bundle)],
            expected={0},
        )
        self.run(
            "migration_frozen_v2_rejects_bplus_bundle",
            ["verify", "--json", str(bplus_bundle)],
            expected={2},
            executable=legacy_install,
        )

        for source in (legacy_bundle, checkpoint, bplus_bundle):
            if source.is_file():
                shutil.copyfile(source, self.artifacts / source.name)
            else:
                self.failures.append(f"migration public artifact is missing: {source.name}")
        shutil.rmtree(legacy_home)
        migration_recovery.unlink(missing_ok=True)
        legacy_install.unlink(missing_ok=True)
        if legacy_home.exists() or migration_recovery.exists():
            self.failures.append("migration qualification cleanup left private state behind")
        return {
            "legacy_binary_sha256": sha256(legacy_binary),
            "legacy_key_id": legacy_key_id,
            "identity_id": identity_id,
            "frozen_v2_exit_code": frozen_attempt.returncode,
            "frozen_v2_executed_sentinel": sentinel.exists(),
            "frozen_v2_changed_home": before_downgrade != after_downgrade,
        }

    def cleanup(self) -> None:
        shutil.rmtree(self.workspace, ignore_errors=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifact", "--binary", dest="artifact", type=Path, required=True)
    parser.add_argument("--expected-sha256", required=True)
    parser.add_argument("--python-verifier", type=Path)
    parser.add_argument("--expected-python-verifier-sha256")
    parser.add_argument("--legacy-binary", type=Path)
    parser.add_argument("--expected-legacy-sha256")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    artifact = args.artifact.resolve()
    output = args.output.resolve()
    if output.exists():
        raise SystemExit(f"output already exists: {output}")
    artifact_hash = sha256(artifact)
    if artifact_hash != args.expected_sha256.lower():
        raise SystemExit("artifact checksum does not match the expected release hash")
    if args.python_verifier:
        if not args.expected_python_verifier_sha256:
            raise SystemExit("--expected-python-verifier-sha256 is required with --python-verifier")
        if sha256(args.python_verifier.resolve()) != args.expected_python_verifier_sha256.lower():
            raise SystemExit("Python verifier checksum does not match the expected release hash")
    if args.legacy_binary:
        if not args.expected_legacy_sha256:
            raise SystemExit("--expected-legacy-sha256 is required with --legacy-binary")
        if sha256(args.legacy_binary.resolve()) != args.expected_legacy_sha256.lower():
            raise SystemExit("legacy binary checksum does not match the expected frozen-v2 hash")

    output.mkdir(parents=True)
    extraction: Path | None = None
    try:
        binary, extraction, artifact_kind = prepare_binary(artifact)
    except Exception as error:
        result = {
            "schema": "ueg.native-release-qualification.v1",
            "platform": sys.platform,
            "machine": platform.machine(),
            "input_artifact_sha256": artifact_hash,
            "input_artifact_kind": "invalid",
            "binary_sha256": "",
            "signing_key_id": "",
            "commands": [],
            "failures": [f"acquisition failed: {type(error).__name__}: {error}"],
            "passed": False,
        }
        write_json(output / "NATIVE_RELEASE_QUALIFICATION.json", result)
        print(json.dumps(result, indent=2))
        return 1
    walkthrough = Walkthrough(binary, output, artifact_hash, artifact_kind)
    try:
        result = walkthrough.execute(
            args.python_verifier.resolve() if args.python_verifier else None,
            args.legacy_binary.resolve() if args.legacy_binary else None,
        )
    except Exception as error:
        walkthrough.failures.append(f"qualification harness failed: {type(error).__name__}: {error}")
        result = {
            "schema": "ueg.native-release-qualification.v1",
            "platform": sys.platform,
            "machine": platform.machine(),
            "input_artifact_sha256": artifact_hash,
            "input_artifact_kind": artifact_kind,
            "binary_sha256": sha256(binary),
            "signing_key_id": "",
            "commands": walkthrough.commands,
            "failures": walkthrough.failures,
            "passed": False,
        }
    finally:
        walkthrough.cleanup()
        if extraction is not None:
            shutil.rmtree(extraction, ignore_errors=True)
    write_json(output / "NATIVE_RELEASE_QUALIFICATION.json", result)
    hashes = []
    for path in sorted(output.rglob("*")):
        if path.is_file() and path.name != "SHA256SUMS":
            hashes.append(f"{sha256(path)}  {path.relative_to(output).as_posix()}\n")
    (output / "SHA256SUMS").write_text("".join(hashes), encoding="utf-8", newline="\n")
    print(json.dumps(result, indent=2))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
