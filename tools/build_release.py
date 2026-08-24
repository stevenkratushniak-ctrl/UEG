from __future__ import annotations

import argparse
from datetime import datetime, timezone
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import tarfile
import tempfile
import zipfile

from generate_sbom import generate as generate_sbom
from package_python_verifier import package as package_python_verifier


PLATFORMS = (
    ("linux", "amd64", ""),
    ("linux", "arm64", ""),
    ("darwin", "amd64", ""),
    ("darwin", "arm64", ""),
    ("windows", "amd64", ".exe"),
)
PACKAGE_DOCS = (
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
    "LICENSE",
)
PACKAGE_DEMOS = (
    "demo/demo.sh",
    "demo/demo.ps1",
)
FIXED_ZIP_TIME = (1980, 1, 1, 0, 0, 0)


def run(repo: Path, command: list[str], env: dict[str, str] | None = None) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        command,
        cwd=repo,
        env=env,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def git(repo: Path, *args: str) -> str:
    result = run(repo, ["git", *args])
    if result.returncode != 0:
        raise RuntimeError(result.stderr.decode("utf-8", errors="replace"))
    return result.stdout.decode("utf-8").strip()


def write_log(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def add_zip_member(archive: zipfile.ZipFile, name: str, data: bytes, mode: int) -> None:
    info = zipfile.ZipInfo(name, FIXED_ZIP_TIME)
    info.create_system = 3
    info.external_attr = (0o100000 | mode) << 16
    info.compress_type = zipfile.ZIP_DEFLATED
    archive.writestr(info, data, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)


def build_zip(path: Path, root_name: str, members: list[tuple[str, bytes, int]]) -> None:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for relative, data, mode in sorted(members):
            add_zip_member(archive, f"{root_name}/{relative}", data, mode)


def build_tar(path: Path, root_name: str, members: list[tuple[str, bytes, int]]) -> None:
    with path.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0, compresslevel=9) as gz:
            with tarfile.open(fileobj=gz, mode="w", format=tarfile.PAX_FORMAT) as archive:
                for relative, data, mode in sorted(members):
                    info = tarfile.TarInfo(str(PurePosixPath(root_name, relative)))
                    info.size = len(data)
                    info.mode = mode
                    info.mtime = 0
                    info.uid = 0
                    info.gid = 0
                    info.uname = ""
                    info.gname = ""
                    archive.addfile(info, io.BytesIO(data))


def build_source_archive(repo: Path, output: Path, version: str) -> None:
    result = run(repo, ["git", "ls-files", "--stage", "-z"])
    if result.returncode != 0:
        raise RuntimeError(result.stderr.decode("utf-8", errors="replace"))
    members = []
    for entry in result.stdout.decode("utf-8").split("\0"):
        if not entry:
            continue
        metadata, relative = entry.split("\t", 1)
        git_mode = metadata.split(" ", 1)[0]
        source = repo / relative
        if source.is_file():
            mode = 0o755 if git_mode == "100755" else 0o644
            members.append((PurePosixPath(relative).as_posix(), source.read_bytes(), mode))
    build_tar(output, f"ueg-{version}-source", members)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--allow-dirty", action="store_true")
    args = parser.parse_args()

    repo = Path(__file__).resolve().parents[1]
    output = args.output.resolve()
    if output.exists():
        raise SystemExit(f"release output already exists; choose a new path: {output}")
    status = git(repo, "status", "--porcelain", "--untracked-files=all")
    if status and not args.allow_dirty:
        raise SystemExit("release builds require a clean source tree")

    commit = git(repo, "rev-parse", "HEAD")
    commit_time = git(repo, "show", "-s", "--format=%ct", "HEAD")
    staging = Path(tempfile.mkdtemp(prefix=f".{output.name}.building-", dir=output.parent))
    published = False
    try:
        (staging / "logs").mkdir()
        ldflags = f"-s -w -buildid= -X main.Version={args.version}"
        artifact_names: list[str] = []
        binary_names: dict[tuple[str, str], str] = {}
        for operating_system, architecture, extension in PLATFORMS:
            name = f"ueg-{operating_system}-{architecture}{extension}"
            binary_names[(operating_system, architecture)] = name
            env = os.environ.copy()
            env.update(
                {
                    "CGO_ENABLED": "0",
                    "GOOS": operating_system,
                    "GOARCH": architecture,
                    "SOURCE_DATE_EPOCH": commit_time,
                }
            )
            result = run(
                repo,
                [
                    "go",
                    "build",
                    "-trimpath",
                    "-buildvcs=false",
                    "-ldflags",
                    ldflags,
                    "-o",
                    str(staging / name),
                    "./cmd/ueg",
                ],
                env,
            )
            write_log(staging / "logs" / f"{name}.stdout.log", result.stdout)
            write_log(staging / "logs" / f"{name}.stderr.log", result.stderr)
            if result.returncode != 0:
                raise RuntimeError(f"build failed for {operating_system}/{architecture}")
            artifact_names.append(name)

        verifier_name = "ueg-python-verifier.zip"
        package_python_verifier(repo, staging / verifier_name)
        artifact_names.append(verifier_name)

        sbom_name = "UEG.spdx.json"
        (staging / sbom_name).write_text(
            json.dumps(generate_sbom(repo, args.version), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        artifact_names.append(sbom_name)

        docs = [(name, (repo / name).read_bytes(), 0o644) for name in PACKAGE_DOCS]
        docs.extend(
            (name, (repo / name).read_bytes(), 0o755 if name.endswith(".sh") else 0o644)
            for name in PACKAGE_DEMOS
        )
        docs.extend(
            (schema.relative_to(repo).as_posix(), schema.read_bytes(), 0o644)
            for schema in sorted((repo / "contract" / "schemas").glob("*.json"))
        )
        for operating_system, architecture, extension in PLATFORMS:
            binary_name = binary_names[(operating_system, architecture)]
            installed_name = "ueg.exe" if operating_system == "windows" else "ueg"
            members = docs + [
                (installed_name, (staging / binary_name).read_bytes(), 0o755),
                (sbom_name, (staging / sbom_name).read_bytes(), 0o644),
            ]
            root_name = f"ueg-{args.version}-{operating_system}-{architecture}"
            if operating_system == "windows":
                archive_name = root_name + ".zip"
                build_zip(staging / archive_name, root_name, members)
            else:
                archive_name = root_name + ".tar.gz"
                build_tar(staging / archive_name, root_name, members)
            artifact_names.append(archive_name)

        expected_artifacts = {
            "schema": "ueg.native-qualification-inputs.v1",
            "version": args.version,
            "source_commit": commit,
            "artifacts": {
                name: sha256(staging / name)
                for name in sorted(
                    candidate
                    for candidate in artifact_names
                    if candidate == verifier_name
                    or candidate.startswith("ueg-")
                    and candidate != "ueg-native-qualification-kit.zip"
                )
            },
        }
        kit_name = "ueg-native-qualification-kit.zip"
        kit_members = [
            ("README.md", (repo / "qualification" / "README.md").read_bytes(), 0o644),
            (
                "native_release_walkthrough.py",
                (repo / "qualification" / "native_release_walkthrough.py").read_bytes(),
                0o755,
            ),
            (
                "EXPECTED_ARTIFACTS.json",
                (json.dumps(expected_artifacts, indent=2, sort_keys=True) + "\n").encode(),
                0o644,
            ),
        ]
        build_zip(staging / kit_name, f"ueg-{args.version}-native-qualification", kit_members)
        artifact_names.append(kit_name)

        source_name = f"ueg-{args.version}-source.tar.gz"
        build_source_archive(repo, staging / source_name, args.version)
        artifact_names.append(source_name)

        artifacts = [
            {
                "file": name,
                "bytes": (staging / name).stat().st_size,
                "sha256": sha256(staging / name),
            }
            for name in sorted(artifact_names)
        ]
        go_version = run(repo, ["go", "version"]).stdout.decode().strip()
        python_version = run(repo, [os.fspath(Path(os.sys.executable)), "--version"]).stdout.decode().strip()
        provenance = {
            "schema": "ueg.release-build-provenance.v3",
            "product": "UEG",
            "version": args.version,
            "source_commit": commit,
            "source_tree_clean": not bool(status),
            "source_date_epoch": int(commit_time),
            "go_version": go_version,
            "python_version": python_version,
            "go_build_flags": ["-trimpath", "-buildvcs=false", "-ldflags", ldflags],
            "artifacts": artifacts,
        }
        provenance_path = staging / "BUILD_PROVENANCE.json"
        provenance_path.write_text(
            json.dumps(provenance, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
            newline="\n",
        )

        sums_files = sorted(artifact_names + ["BUILD_PROVENANCE.json"])
        sums = "".join(f"{sha256(staging / name)}  {name}\n" for name in sums_files)
        (staging / "SHA256SUMS").write_text(sums, encoding="utf-8", newline="\n")

        # Build logs are failure evidence, not release assets. Keep them in a
        # preserved .failed directory on failure, but never publish them beside
        # the checksummed deliverables after a successful build.
        shutil.rmtree(staging / "logs")

        staging.replace(output)
        published = True
        print(json.dumps({"output": str(output), "commit": commit, "artifacts": artifacts}, indent=2))
        return 0
    except Exception:
        failure = output.with_name(output.name + ".failed")
        if failure.exists():
            failure = output.with_name(output.name + f".failed-{os.getpid()}")
        staging.replace(failure)
        raise
    finally:
        if not published and staging.exists():
            shutil.rmtree(staging, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
