from __future__ import annotations

import argparse
import sys
from pathlib import Path


def _read_version(pyproject_path: Path) -> str:
    content = pyproject_path.read_text(encoding="utf-8")
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if line.startswith("version = "):
            value = line.split("=", maxsplit=1)[1].strip().strip('"')
            if value:
                return value
    raise RuntimeError(f"Unable to read version from {pyproject_path}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate git release tag against package versions."
    )
    parser.add_argument(
        "--tag",
        required=True,
        help="Git tag name, expected format vX.Y.Z",
    )
    args = parser.parse_args()
    tag = args.tag.strip()
    if not tag.startswith("v"):
        raise SystemExit("Release tag must start with 'v' (example: v0.1.0)")
    tag_version = tag[1:]
    if tag_version == "":
        raise SystemExit("Release tag version cannot be empty")

    repo_root = Path(__file__).resolve().parents[1]
    contracts_version = _read_version(repo_root / "predicate_contracts" / "pyproject.toml")
    authority_version = _read_version(repo_root / "predicate_authority" / "pyproject.toml")

    if contracts_version != authority_version:
        raise SystemExit(
            "Package versions are not in sync: "
            f"predicate-contracts={contracts_version}, predicate-authority={authority_version}"
        )
    if tag_version != contracts_version:
        raise SystemExit(
            f"Tag version {tag_version} does not match package version {contracts_version}"
        )

    print(
        "release tag validated:",
        f"tag={tag}",
        f"predicate-contracts={contracts_version}",
        f"predicate-authority={authority_version}",
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
