from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess
from typing import Any


PYTHON_LICENSES = {
    "attrs": "MIT",
    "cffi": "MIT",
    "cryptography": "Apache-2.0 OR BSD-3-Clause",
    "jsonschema": "MIT",
    "jsonschema-specifications": "MIT",
    "pycparser": "BSD-3-Clause",
    "referencing": "MIT",
    "rpds-py": "MIT",
    "typing-extensions": "PSF-2.0",
}


def run(repo: Path, *command: str) -> str:
    result = subprocess.run(
        command,
        cwd=repo,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
    )
    return result.stdout.strip()


def go_modules(repo: Path) -> list[dict[str, Any]]:
    raw = run(repo, "go", "list", "-m", "-json", "all")
    decoder = json.JSONDecoder()
    modules: list[dict[str, Any]] = []
    index = 0
    while index < len(raw):
        value, end = decoder.raw_decode(raw, index)
        modules.append(value)
        index = end
        while index < len(raw) and raw[index].isspace():
            index += 1
    return modules


def python_requirements(repo: Path) -> list[tuple[str, str]]:
    requirements: list[tuple[str, str]] = []
    for line in (repo / "requirements.lock").read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "==" not in line:
            raise ValueError(f"requirements.lock entry is not exact: {line}")
        name, version = line.split("==", 1)
        normalized = name.lower().replace("_", "-")
        if normalized not in PYTHON_LICENSES:
            raise ValueError(f"no reviewed license mapping for {name}")
        requirements.append((normalized, version))
    return sorted(requirements)


def spdx_id(kind: str, name: str) -> str:
    clean = re.sub(r"[^A-Za-z0-9.-]", "-", name)
    return f"SPDXRef-{kind}-{clean}"


def package(
    *, name: str, version: str, license_id: str, purl: str, supplier: str = "NOASSERTION"
) -> dict[str, Any]:
    return {
        "SPDXID": spdx_id("Package", name),
        "name": name,
        "versionInfo": version,
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": False,
        "licenseConcluded": license_id,
        "licenseDeclared": license_id,
        "copyrightText": "NOASSERTION",
        "supplier": supplier,
        "externalRefs": [
            {
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": purl,
            }
        ],
    }


def generate(repo: Path, version: str) -> dict[str, Any]:
    commit = run(repo, "git", "rev-parse", "HEAD")
    commit_time = run(repo, "git", "show", "-s", "--format=%cI", "HEAD")
    created = datetime.fromisoformat(commit_time).astimezone(timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    namespace_hash = hashlib.sha256(f"{commit}:{version}".encode()).hexdigest()

    product = package(
        name="UEG",
        version=version,
        license_id="MIT",
        purl=f"pkg:golang/github.com/stevenkratushniak-ctrl/ueg@{version}",
        supplier="Person: Steven Kratushniak",
    )
    verifier = package(
        name="UEG-Python-Verifier",
        version=version,
        license_id="MIT",
        purl=f"pkg:generic/ueg-python-verifier@{version}",
        supplier="Person: Steven Kratushniak",
    )
    packages = [product, verifier]
    relationships: list[dict[str, str]] = [
        {
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": product["SPDXID"],
        },
        {
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": verifier["SPDXID"],
        },
    ]

    for module in go_modules(repo):
        if module.get("Main"):
            continue
        path = module["Path"]
        dep = package(
            name=path,
            version=module["Version"],
            license_id="BSD-3-Clause" if path.startswith("golang.org/x/") else "NOASSERTION",
            purl=f"pkg:golang/{path}@{module['Version']}",
        )
        packages.append(dep)
        relationships.append(
            {
                "spdxElementId": product["SPDXID"],
                "relationshipType": "DEPENDS_ON",
                "relatedSpdxElement": dep["SPDXID"],
            }
        )

    for name, dependency_version in python_requirements(repo):
        dep = package(
            name=name,
            version=dependency_version,
            license_id=PYTHON_LICENSES[name],
            purl=f"pkg:pypi/{name}@{dependency_version}",
        )
        packages.append(dep)
        relationships.append(
            {
                "spdxElementId": verifier["SPDXID"],
                "relationshipType": "DEPENDS_ON",
                "relatedSpdxElement": dep["SPDXID"],
            }
        )

    packages.sort(key=lambda item: item["SPDXID"])
    relationships.sort(
        key=lambda item: (
            item["spdxElementId"], item["relationshipType"], item["relatedSpdxElement"]
        )
    )
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"UEG-{version}",
        "documentNamespace": f"https://ueg.invalid/spdx/{namespace_hash}",
        "creationInfo": {
            "created": created,
            "creators": ["Tool: UEG deterministic release builder"],
            "licenseListVersion": "3.25",
        },
        "documentDescribes": [product["SPDXID"], verifier["SPDXID"]],
        "packages": packages,
        "relationships": relationships,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    document = generate(args.repo.resolve(), args.version)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
