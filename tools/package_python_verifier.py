from __future__ import annotations

import argparse
from pathlib import Path
import zipfile


FIXED_TIME = (1980, 1, 1, 0, 0, 0)


def package(repo: Path, output: Path) -> None:
    members = [
        repo / "requirements.lock",
        repo / "LICENSE",
        repo / "THIRD_PARTY_NOTICES.md",
    ]
    members.extend(sorted((repo / "verifier").glob("*.py")))
    members.append(repo / "verifier" / "README.md")
    members.extend(sorted((repo / "contract" / "schemas").glob("*.json")))
    missing = [path for path in members if not path.is_file()]
    if missing:
        raise FileNotFoundError(f"missing verifier package members: {missing}")

    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_suffix(output.suffix + ".tmp")
    temporary.unlink(missing_ok=True)
    with zipfile.ZipFile(
        temporary,
        mode="w",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=9,
        strict_timestamps=True,
    ) as archive:
        for source in sorted(members, key=lambda item: item.relative_to(repo).as_posix()):
            relative = source.relative_to(repo).as_posix()
            info = zipfile.ZipInfo(relative, FIXED_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            info.create_system = 3
            archive.writestr(info, source.read_bytes(), compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
    temporary.replace(output)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[1]
    package(repo, args.output.resolve())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
