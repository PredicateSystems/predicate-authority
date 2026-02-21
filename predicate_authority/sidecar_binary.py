"""
Sidecar binary management for predicate-authority.

This module provides utilities for downloading, locating, and running
the Predicate Authority sidecar binary.

Usage:
    from predicate_authority.sidecar_binary import (
        get_sidecar_path,
        is_sidecar_available,
        download_sidecar,
        run_sidecar,
    )

    # Check if sidecar is available
    if not is_sidecar_available():
        download_sidecar()

    # Run sidecar
    process = run_sidecar(port=8787, policy_file="policy.json")
"""

from __future__ import annotations

import hashlib
import os
import platform
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path
from urllib.request import urlopen

# GitHub release configuration
ALLOWED_URL_PREFIXES = (
    "https://api.github.com/",
    "https://github.com/",
)


def _safe_urlopen(url: str, *, timeout: int = 30):  # noqa: ANN201
    """
    Open a URL with scheme validation to prevent file:// and other attacks.

    Only allows HTTPS URLs to trusted GitHub domains.
    """
    if not url.startswith(ALLOWED_URL_PREFIXES):
        raise ValueError(f"URL must start with one of {ALLOWED_URL_PREFIXES}, got: {url}")
    return urlopen(url, timeout=timeout)  # nosec B310


SIDECAR_REPO = "PredicateSystems/predicate-authority-sidecar"
SIDECAR_BINARY_NAME = "predicate-authorityd"

# Platform mapping: (system, machine) -> artifact name
PLATFORM_MAP = {
    ("Darwin", "arm64"): "predicate-authorityd-darwin-arm64",
    ("Darwin", "x86_64"): "predicate-authorityd-darwin-x64",
    ("Linux", "x86_64"): "predicate-authorityd-linux-x64",
    ("Linux", "aarch64"): "predicate-authorityd-linux-arm64",
    ("Windows", "AMD64"): "predicate-authorityd-windows-x64",
}


def get_platform_key() -> str:
    """Get the platform key for the current system."""
    system = platform.system()
    machine = platform.machine()

    key = PLATFORM_MAP.get((system, machine))
    if not key:
        raise RuntimeError(
            f"Unsupported platform: {system} {machine}. "
            f"Supported platforms: {list(PLATFORM_MAP.keys())}"
        )
    return key


def get_sidecar_dir() -> Path:
    """Get the directory where sidecar binaries are stored."""
    # Use platform-appropriate data directory
    if sys.platform == "win32":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support"
    else:
        base = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))

    sidecar_dir = base / "predicate-authority" / "bin"
    sidecar_dir.mkdir(parents=True, exist_ok=True)
    return sidecar_dir


def get_sidecar_path() -> Path:
    """
    Get the path to the sidecar binary.

    Returns the path if found, raises RuntimeError if not available.

    Search order:
    1. PREDICATE_SIDECAR_PATH environment variable
    2. Bundled binary in package
    3. Downloaded binary in data directory
    4. Binary in PATH
    """
    binary_name = SIDECAR_BINARY_NAME
    if sys.platform == "win32":
        binary_name += ".exe"

    # 1. Check environment variable
    env_path = os.environ.get("PREDICATE_SIDECAR_PATH")
    if env_path:
        path = Path(env_path)
        if path.exists():
            return path

    # 2. Check bundled binary (in package bin/ directory)
    pkg_bin = Path(__file__).parent / "bin" / binary_name
    if pkg_bin.exists():
        return pkg_bin

    # 3. Check downloaded binary
    downloaded = get_sidecar_dir() / binary_name
    if downloaded.exists():
        return downloaded

    # 4. Check PATH
    path_binary = shutil.which(binary_name)
    if path_binary:
        return Path(path_binary)

    raise RuntimeError(
        f"Sidecar binary not found. Install with:\n"
        f"  pip install predicate-authority[sidecar]\n"
        f"Or download manually from:\n"
        f"  https://github.com/{SIDECAR_REPO}/releases"
    )


def is_sidecar_available() -> bool:
    """Check if the sidecar binary is available."""
    try:
        get_sidecar_path()
        return True
    except RuntimeError:
        return False


def get_latest_version() -> str:
    """Get the latest sidecar version from GitHub."""
    import json

    url = f"https://api.github.com/repos/{SIDECAR_REPO}/releases/latest"
    with _safe_urlopen(url, timeout=30) as response:
        data = json.loads(response.read().decode())
        tag_name: str = data["tag_name"]
        return tag_name


def download_sidecar(
    version: str | None = None,
    target_dir: Path | None = None,
    verify_checksum: bool = True,
) -> Path:
    """
    Download the sidecar binary for the current platform.

    Args:
        version: Version to download (e.g., "v0.1.0"). If None, downloads latest.
        target_dir: Directory to place binary. Defaults to data directory.
        verify_checksum: Whether to verify SHA256 checksum.

    Returns:
        Path to the downloaded binary.
    """
    if version is None:
        version = get_latest_version()

    platform_key = get_platform_key()
    is_windows = sys.platform == "win32"

    # Determine artifact names
    if is_windows:
        artifact_name = f"{platform_key}.zip"
        binary_name = f"{SIDECAR_BINARY_NAME}.exe"
    else:
        artifact_name = f"{platform_key}.tar.gz"
        binary_name = SIDECAR_BINARY_NAME

    # Download URLs
    base_url = f"https://github.com/{SIDECAR_REPO}/releases/download/{version}"
    artifact_url = f"{base_url}/{artifact_name}"
    checksum_url = f"{artifact_url}.sha256"

    target_dir = target_dir or get_sidecar_dir()
    target_dir.mkdir(parents=True, exist_ok=True)
    target_path = target_dir / binary_name

    print(f"Downloading sidecar {version} for {platform_key}...")

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        archive_path = tmp_path / artifact_name

        # Download archive
        print(f"  Fetching {artifact_url}")
        with _safe_urlopen(artifact_url, timeout=120) as response:
            archive_path.write_bytes(response.read())

        # Verify checksum
        if verify_checksum:
            print("  Verifying checksum...")
            with _safe_urlopen(checksum_url, timeout=30) as response:
                expected_checksum = response.read().decode().split()[0].lower()

            actual_checksum = hashlib.sha256(archive_path.read_bytes()).hexdigest()
            if actual_checksum != expected_checksum:
                raise RuntimeError(
                    f"Checksum mismatch!\n"
                    f"  Expected: {expected_checksum}\n"
                    f"  Actual:   {actual_checksum}"
                )

        # Extract binary
        print("  Extracting...")
        if is_windows:
            with zipfile.ZipFile(archive_path, "r") as zf:
                zf.extract(binary_name, tmp_path)
        else:
            with tarfile.open(archive_path, "r:gz") as tf:
                tf.extract(binary_name, tmp_path)

        # Move to target
        extracted_binary = tmp_path / binary_name
        shutil.move(str(extracted_binary), str(target_path))

        # Make executable on Unix
        if not is_windows:
            target_path.chmod(
                target_path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
            )

    print(f"  Installed to: {target_path}")
    return target_path


def run_sidecar(
    *,
    host: str = "127.0.0.1",
    port: int = 8787,
    mode: str = "local_only",
    policy_file: str | Path | None = None,
    identity_file: str | Path | None = None,
    log_level: str = "info",
    control_plane_url: str | None = None,
    tenant_id: str | None = None,
    project_id: str | None = None,
    api_key: str | None = None,
    sync_enabled: bool = False,
    fail_open: bool = False,
    capture_output: bool = False,
) -> subprocess.Popen[bytes]:
    """
    Run the sidecar process.

    Args:
        host: Host to bind to.
        port: Port to bind to.
        mode: Operating mode (local_only or cloud_connected).
        policy_file: Path to policy JSON file.
        identity_file: Path to local identity registry.
        log_level: Log level (trace, debug, info, warn, error).
        control_plane_url: Control-plane URL.
        tenant_id: Tenant ID.
        project_id: Project ID.
        api_key: API key (prefer PREDICATE_API_KEY env var).
        sync_enabled: Enable control-plane sync.
        fail_open: Fail open if control-plane unreachable.
        capture_output: Capture stdout/stderr instead of inheriting.

    Returns:
        subprocess.Popen instance for the sidecar process.

    Example:
        >>> process = run_sidecar(port=8787, policy_file="policy.json")
        >>> # Later...
        >>> process.terminate()
        >>> process.wait()
    """
    binary_path = get_sidecar_path()

    args = [str(binary_path), "run"]
    args.extend(["--host", host])
    args.extend(["--port", str(port)])
    args.extend(["--mode", mode])

    if policy_file:
        args.extend(["--policy-file", str(policy_file)])
    if identity_file:
        args.extend(["--identity-file", str(identity_file)])
    if log_level:
        args.extend(["--log-level", log_level])
    if control_plane_url:
        args.extend(["--control-plane-url", control_plane_url])
    if tenant_id:
        args.extend(["--tenant-id", tenant_id])
    if project_id:
        args.extend(["--project-id", project_id])
    if api_key:
        args.extend(["--predicate-api-key", api_key])
    if sync_enabled:
        args.append("--sync-enabled")
    if fail_open:
        args.append("--fail-open")

    if capture_output:
        return subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)  # nosec B603
    return subprocess.Popen(args)  # nosec B603


def get_sidecar_version() -> str:
    """Get the version of the installed sidecar binary."""
    binary_path = get_sidecar_path()
    result = subprocess.run(  # nosec B603 - binary_path is from get_sidecar_path()
        [str(binary_path), "--version"],
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


def _cli_download() -> None:
    """CLI entry point for downloading the sidecar binary."""
    import argparse

    parser = argparse.ArgumentParser(description="Download the Predicate Authority sidecar binary")
    parser.add_argument(
        "--version",
        help="Version to download (e.g., v0.1.0). Defaults to latest.",
    )
    parser.add_argument(
        "--target-dir",
        type=Path,
        help="Directory to install binary. Defaults to platform data directory.",
    )
    parser.add_argument(
        "--skip-checksum",
        action="store_true",
        help="Skip SHA256 checksum verification.",
    )
    args = parser.parse_args()

    try:
        path = download_sidecar(
            version=args.version,
            target_dir=args.target_dir,
            verify_checksum=not args.skip_checksum,
        )
        print(f"\nSidecar binary installed at: {path}")
        print(f"Run with: {path} run --help")
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


__all__ = [
    "get_sidecar_path",
    "is_sidecar_available",
    "download_sidecar",
    "run_sidecar",
    "get_sidecar_version",
    "get_platform_key",
    "get_sidecar_dir",
]
