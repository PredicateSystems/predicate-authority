from __future__ import annotations

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

TEXT_SUFFIX_ALLOWLIST = {
    ".py",
    ".md",
    ".txt",
    ".yml",
    ".yaml",
    ".json",
    ".toml",
    ".ini",
    ".cfg",
    ".env",
    ".example",
}

EXCLUDED_DIRS = {
    ".git",
    ".venv",
    "venv",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".cursor",
}

SECRET_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?i)\bOKTA_CLIENT_SECRET\s*=\s*(?![\"']?<)(?![\"']?your-)[\"']?[^\"'\s]+"),
    re.compile(r"(?i)\bOKTA_API_TOKEN\s*=\s*(?![\"']?<)(?![\"']?your-)[\"']?[^\"'\s]+"),
    re.compile(r"(?i)\bOKTA_PRIVATE_KEY\s*=\s*(?![\"']?<)(?![\"']?your-)[\"']?[^\"'\s]+"),
)


def _should_scan(path: Path) -> bool:
    if any(part in EXCLUDED_DIRS for part in path.parts):
        return False
    if path.name.startswith(".") and path.suffix == "":
        return False
    if path.suffix in TEXT_SUFFIX_ALLOWLIST:
        return True
    # Include common dotfiles without suffix.
    if path.name in {".env", ".env.example", ".gitignore"}:
        return True
    return False


def _iter_text_files(root: Path) -> list[Path]:
    paths: list[Path] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if _should_scan(path):
            paths.append(path)
    return paths


def main() -> int:
    violations: list[str] = []
    for file_path in _iter_text_files(REPO_ROOT):
        try:
            content = file_path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for idx, line in enumerate(content.splitlines(), start=1):
            if "OKTA_" not in line.upper():
                continue
            for pattern in SECRET_PATTERNS:
                if pattern.search(line):
                    rel = file_path.relative_to(REPO_ROOT)
                    violations.append(f"{rel}:{idx}: potential plaintext Okta secret")
                    break
    if violations:
        print("Found potential plaintext Okta secrets:")
        for item in violations:
            print(f" - {item}")
        return 1
    print("No plaintext Okta secrets detected.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
