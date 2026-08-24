from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import stat
import tarfile
import zipfile


DEVELOPER_MARKERS = (
    b"GITHUB_TOKEN=",
    b"C:\\UEG_",
    b"C:/UEG_",
    b"C:\\Users\\steve",
    b"C:/Users/steve",
)
PRIVATE_KEY_PEM = re.compile(
    rb"(?:^|\r?\n)-----BEGIN (?:ENCRYPTED |RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----\r?(?:\n|$)"
)
MAX_ARCHIVE_MEMBERS = 4096
MAX_ARCHIVE_MEMBER_BYTES = 256 * 1024 * 1024
MAX_ARCHIVE_TOTAL_BYTES = 512 * 1024 * 1024
PLATFORMS = (
    ("linux", "amd64", "", ".tar.gz"),
    ("linux", "arm64", "", ".tar.gz"),
    ("darwin", "amd64", "", ".tar.gz"),
    ("darwin", "arm64", "", ".tar.gz"),
    ("windows", "amd64", ".exe", ".zip"),
)
PACKAGE_DOCS = {
    "README.md",
    "INSTALL.md",
    "LIMITS.md",
    "PROVENANCE.md",
    "CHANGELOG.md",
    "RELEASE_NOTES.md",
    "SUPPORTED_PLATFORMS.md",
    "SUPPORT.md",
    "SECURITY.md",
    "THIRD_PARTY_NOTICES.md",
    "REPRODUCIBLE_BUILDS.md",
    "DEMO_TRANSCRIPT.txt",
    "demo.sh",
    "demo.ps1",
    "LICENSE",
    "UEG.spdx.json",
}
BPLUS_SCHEMAS = {
    "evidence_anchor.v1.schema.json",
    "identity_card.v1.schema.json",
    "identity_genesis.v1.schema.json",
    "identity_home.v1.schema.json",
    "identity_lifecycle_record.v1.schema.json",
    "lifecycle_checkpoint.v1.schema.json",
    "recovery_package.v1.schema.json",
}


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def read_sums(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([^/\\]+)", line)
        if not match:
            raise ValueError(f"malformed checksum line: {line!r}")
        checksum, name = match.groups()
        if name in values:
            raise ValueError(f"duplicate checksum entry: {name}")
        values[name] = checksum
    return values


def strict_json_bytes(data: bytes, source: str) -> object:
    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        output: dict[str, object] = {}
        for key, value in pairs:
            if key in output:
                raise ValueError(f"duplicate JSON field {key!r} in {source}")
            output[key] = value
        return output

    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"invalid JSON in {source}: {error}") from error


def strict_json_file(path: Path) -> object:
    return strict_json_bytes(path.read_bytes(), path.name)


def contains_private_key(data: bytes) -> bool:
    return PRIVATE_KEY_PEM.search(data) is not None


def safe_archive_name(name: str, archive: str) -> str:
    normalized = name.replace("\\", "/")
    path = PurePosixPath(normalized)
    if (
        not normalized
        or normalized.startswith("/")
        or any(part in {"", ".", ".."} for part in path.parts)
        or (path.parts and ":" in path.parts[0])
    ):
        raise ValueError(f"unsafe archive member {name!r} in {archive}")
    return normalized


def archive_members(path: Path) -> list[tuple[str, bytes]]:
    if path.suffix == ".zip":
        with zipfile.ZipFile(path) as archive:
            infos = archive.infolist()
            if len(infos) > MAX_ARCHIVE_MEMBERS:
                raise ValueError(f"too many members in {path.name}")
            output: list[tuple[str, bytes]] = []
            seen: set[str] = set()
            total = 0
            for info in infos:
                if info.is_dir():
                    raise ValueError(f"directory member {info.filename!r} in {path.name}")
                normalized = safe_archive_name(info.filename, path.name)
                identity = normalized.casefold()
                if identity in seen:
                    raise ValueError(f"duplicate member {info.filename!r} in {path.name}")
                seen.add(identity)
                if info.flag_bits & 0x1:
                    raise ValueError(f"encrypted member {info.filename!r} in {path.name}")
                file_type = (info.external_attr >> 16) & 0o170000
                if file_type not in {0, stat.S_IFREG}:
                    raise ValueError(f"non-file member {info.filename!r} in {path.name}")
                if info.file_size > MAX_ARCHIVE_MEMBER_BYTES:
                    raise ValueError(f"oversized member {info.filename!r} in {path.name}")
                total += info.file_size
                if total > MAX_ARCHIVE_TOTAL_BYTES:
                    raise ValueError(f"archive expands beyond limit: {path.name}")
                output.append((normalized, archive.read(info)))
            return output
    if path.name.endswith(".tar.gz"):
        with tarfile.open(path, mode="r:gz") as archive:
            members = archive.getmembers()
            if len(members) > MAX_ARCHIVE_MEMBERS:
                raise ValueError(f"too many members in {path.name}")
            output: list[tuple[str, bytes]] = []
            seen: set[str] = set()
            total = 0
            for member in members:
                if not member.isfile():
                    raise ValueError(f"non-file member {member.name!r} in {path.name}")
                normalized = safe_archive_name(member.name, path.name)
                identity = normalized.casefold()
                if identity in seen:
                    raise ValueError(f"duplicate member {member.name!r} in {path.name}")
                seen.add(identity)
                if member.size > MAX_ARCHIVE_MEMBER_BYTES:
                    raise ValueError(f"oversized member {member.name!r} in {path.name}")
                total += member.size
                if total > MAX_ARCHIVE_TOTAL_BYTES:
                    raise ValueError(f"archive expands beyond limit: {path.name}")
                handle = archive.extractfile(member)
                if handle is None:
                    raise ValueError(f"cannot read {member.name}")
                output.append((normalized, handle.read()))
            return output
    return []


def expected_artifacts(version: str) -> set[str]:
    if not re.fullmatch(r"[0-9A-Za-z][0-9A-Za-z._-]*", version):
        raise ValueError(f"unsafe release version: {version!r}")
    names = {
        "ueg-python-verifier.zip",
        "ueg-native-qualification-kit.zip",
        "UEG.spdx.json",
        f"ueg-{version}-source.tar.gz",
    }
    for operating_system, architecture, executable_suffix, archive_suffix in PLATFORMS:
        names.add(f"ueg-{operating_system}-{architecture}{executable_suffix}")
        names.add(f"ueg-{version}-{operating_system}-{architecture}{archive_suffix}")
    return names


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("release", type=Path)
    args = parser.parse_args()
    root = args.release.resolve()
    expected = read_sums(root / "SHA256SUMS")
    failures: list[str] = []
    checked = 0
    actual_root_files = {path.name for path in root.iterdir() if path.is_file()}
    expected_root_files = set(expected) | {"SHA256SUMS"}
    for name in sorted(actual_root_files - expected_root_files):
        failures.append(f"unchecksummed extra release file: {name}")
    for path in sorted(root.iterdir()):
        if path.is_dir():
            failures.append(f"unexpected release directory: {path.name}")
    for name, checksum in sorted(expected.items()):
        path = root / name
        if not path.is_file():
            failures.append(f"missing {name}")
            continue
        actual = digest(path)
        checked += 1
        if actual != checksum:
            failures.append(f"checksum mismatch for {name}")

        data = path.read_bytes()
        if name.startswith("ueg-") and not name.endswith((".zip", ".tar.gz")):
            for marker in DEVELOPER_MARKERS:
                if marker in data:
                    failures.append(f"forbidden private/developer marker in {name}")
            if contains_private_key(data):
                failures.append(f"private key in {name}")

        try:
            for member_name, member_data in archive_members(path):
                if contains_private_key(member_data):
                    failures.append(f"private key in {name}:{member_name}")
        except Exception as error:
            failures.append(f"archive validation failed for {name}: {error}")

    provenance = strict_json_file(root / "BUILD_PROVENANCE.json")
    if not isinstance(provenance, dict):
        raise ValueError("BUILD_PROVENANCE.json must contain an object")
    if provenance.get("schema") != "ueg.release-build-provenance.v3":
        failures.append("unexpected build provenance schema")
    if provenance.get("product") != "UEG":
        failures.append("build provenance names the wrong product")
    if not provenance.get("source_tree_clean"):
        failures.append("build provenance does not bind a clean source tree")
    if not re.fullmatch(r"[0-9a-f]{40}", str(provenance.get("source_commit", ""))):
        failures.append("build provenance has an invalid source commit")
    version = str(provenance.get("version", ""))
    required_artifacts = expected_artifacts(version)
    if set(expected) != required_artifacts | {"BUILD_PROVENANCE.json"}:
        failures.append("checksum manifest does not name the exact release artifact set")

    sbom = strict_json_file(root / "UEG.spdx.json")
    if not isinstance(sbom, dict):
        raise ValueError("UEG.spdx.json must contain an object")
    if sbom.get("spdxVersion") != "SPDX-2.3":
        failures.append("SBOM is not SPDX 2.3")
    if sbom.get("name") != f"UEG-{version}":
        failures.append("SBOM version does not match build provenance")

    provenance_artifacts: dict[str, str] = {}
    for item in provenance.get("artifacts", []):
        if not isinstance(item, dict) or not isinstance(item.get("file"), str):
            failures.append("malformed artifact record in build provenance")
            continue
        name = item["file"]
        if name in provenance_artifacts:
            failures.append(f"duplicate artifact record in build provenance: {name}")
            continue
        provenance_artifacts[name] = str(item.get("sha256", ""))
        artifact_path = root / name
        if artifact_path.is_file() and item.get("bytes") != artifact_path.stat().st_size:
            failures.append(f"provenance byte count disagreement for {name}")
    if set(provenance_artifacts) != required_artifacts:
        failures.append("build provenance does not name the exact release artifact set")
    for name, checksum in provenance_artifacts.items():
        if expected.get(name) != checksum:
            failures.append(f"provenance/checksum disagreement for {name}")

    platform_archives = [
        path
        for path in root.iterdir()
        if path.is_file()
        and path.name.startswith("ueg-")
        and (path.suffix == ".zip" or path.name.endswith(".tar.gz"))
        and "source" not in path.name
        and "qualification-kit" not in path.name
        and "python-verifier" not in path.name
    ]
    for archive in platform_archives:
        members = archive_members(archive)
        basenames = {Path(name).name for name, _ in members}
        missing = PACKAGE_DOCS - basenames
        if missing:
            failures.append(f"{archive.name} is missing package files: {sorted(missing)}")
        missing_schemas = BPLUS_SCHEMAS - basenames
        if missing_schemas:
            failures.append(f"{archive.name} is missing B+ contract schemas: {sorted(missing_schemas)}")
        binary_members = [
            data for name, data in members if Path(name).name in {"ueg", "ueg.exe"}
        ]
        if len(binary_members) != 1:
            failures.append(f"{archive.name} does not contain exactly one UEG executable")
            continue
        raw_name = None
        for candidate in expected:
            if not candidate.startswith("ueg-") or candidate.endswith((".zip", ".tar.gz")):
                continue
            if "windows-amd64" in archive.name and candidate == "ueg-windows-amd64.exe":
                raw_name = candidate
            elif "linux-amd64" in archive.name and candidate == "ueg-linux-amd64":
                raw_name = candidate
            elif "linux-arm64" in archive.name and candidate == "ueg-linux-arm64":
                raw_name = candidate
            elif "darwin-amd64" in archive.name and candidate == "ueg-darwin-amd64":
                raw_name = candidate
            elif "darwin-arm64" in archive.name and candidate == "ueg-darwin-arm64":
                raw_name = candidate
        if raw_name is None or binary_members[0] != (root / raw_name).read_bytes():
            failures.append(f"{archive.name} executable does not match its raw release binary")

    source_name = f"ueg-{version}-source.tar.gz"
    source_members = {name for name, _ in archive_members(root / source_name)}
    source_required = {
        f"ueg-{version}-source/go.mod",
        f"ueg-{version}-source/go.sum",
        f"ueg-{version}-source/cmd/ueg/main.go",
        f"ueg-{version}-source/internal/keys/keys.go",
        f"ueg-{version}-source/internal/identity/lifecycle.go",
        f"ueg-{version}-source/verifier/bplus_verify.py",
        f"ueg-{version}-source/contract/schemas/identity_genesis.v1.schema.json",
        f"ueg-{version}-source/requirements.lock",
        f"ueg-{version}-source/.github/workflows/release-qualification.yml",
        f"ueg-{version}-source/LICENSE",
    }
    if not source_required <= source_members:
        failures.append(f"source archive is missing required files: {sorted(source_required - source_members)}")

    verifier_members = {name for name, _ in archive_members(root / "ueg-python-verifier.zip")}
    verifier_required = {
        "requirements.lock",
        "LICENSE",
        "THIRD_PARTY_NOTICES.md",
        "verifier/reality_verify.py",
        "verifier/README.md",
    }
    if not verifier_required <= verifier_members:
        failures.append(
            f"Python verifier package is missing required files: {sorted(verifier_required - verifier_members)}"
        )

    kit_members = dict(archive_members(root / "ueg-native-qualification-kit.zip"))
    expected_input_name = next(
        (name for name in kit_members if Path(name).name == "EXPECTED_ARTIFACTS.json"), None
    )
    if expected_input_name is None:
        failures.append("native qualification kit is missing EXPECTED_ARTIFACTS.json")
    else:
        kit_expected = strict_json_bytes(kit_members[expected_input_name], expected_input_name)
        if not isinstance(kit_expected, dict) or kit_expected.get("source_commit") != provenance.get(
            "source_commit"
        ):
            failures.append("native qualification kit does not bind the release source commit")
        elif kit_expected.get("artifacts") != {
            name: expected[name]
            for name in sorted(required_artifacts)
            if name == "ueg-python-verifier.zip"
            or (name.startswith("ueg-") and "qualification-kit" not in name and "source" not in name)
        }:
            failures.append("native qualification kit artifact hashes do not match the release")

    result = {
        "schema": "ueg.release-package-verification.v1",
        "release": str(root),
        "checksums_checked": checked,
        "failures": failures,
        "passed": not failures,
    }
    print(json.dumps(result, indent=2))
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
