"""
Predicate Authority Sidecar binary installer.

This package automatically downloads the Predicate Authority sidecar binary
during installation via a post-install hook.

The sidecar binary is a Rust-based daemon that provides:
- Policy evaluation
- Mandate signing
- Control-plane sync

Usage:
    pip install predicate-authority-sidecar

Or as an optional dependency:
    pip install predicate-authority[sidecar]

After installation, run:
    predicate-download-sidecar --help
"""

from predicate_authority.sidecar_binary import (
    download_sidecar,
    get_sidecar_path,
    get_sidecar_version,
    is_sidecar_available,
    run_sidecar,
)


# Auto-download on import if not available
def _ensure_sidecar() -> None:
    """Download sidecar if not already available."""
    if not is_sidecar_available():
        print("Sidecar binary not found. Downloading...")
        download_sidecar()


# Trigger download on first import
_ensure_sidecar()

__all__ = [
    "download_sidecar",
    "get_sidecar_path",
    "get_sidecar_version",
    "is_sidecar_available",
    "run_sidecar",
]
