"""
Canonicalization utilities for non-web state evidence.

This module provides consistent normalization for terminal and desktop
accessibility snapshots, ensuring reproducible state hashes across
different runs, platforms, and environments.

Example:
    >>> from predicate_contracts.canonicalization import (
    ...     canonicalize_terminal_snapshot,
    ...     compute_terminal_state_hash,
    ... )
    >>> snapshot = {
    ...     "session_id": "sess-123",
    ...     "cwd": "~/projects/myapp",
    ...     "command": "npm  test",  # Extra whitespace normalized
    ...     "transcript": "\\x1b[32mPASS\\x1b[0m all tests",  # ANSI stripped
    ... }
    >>> state_hash = compute_terminal_state_hash(snapshot)
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

# =============================================================================
# Types
# =============================================================================

Platform = Literal["darwin", "linux", "win32"]

# =============================================================================
# Text Normalization
# =============================================================================


def normalize_text(text: str | None, max_len: int = 80) -> str:
    """
    Normalize text for canonical comparison.

    Transforms:
    - Trims leading/trailing whitespace
    - Collapses internal whitespace to single spaces
    - Lowercases
    - Caps length

    Args:
        text: Input text (may be None)
        max_len: Maximum length to retain (default: 80)

    Returns:
        Normalized text string (empty string if input is None)

    Examples:
        >>> normalize_text("  Hello   World  ")
        'hello world'
        >>> normalize_text(None)
        ''
    """
    if not text:
        return ""

    # Trim and collapse whitespace
    normalized = " ".join(text.split())
    # Lowercase
    normalized = normalized.lower()
    # Cap length
    if len(normalized) > max_len:
        normalized = normalized[:max_len]
    return normalized


def normalize_command(cmd: str | None) -> str:
    """
    Normalize a command string.

    Unlike normalize_text, this preserves case (commands are case-sensitive)
    but still trims and collapses whitespace.

    Args:
        cmd: Command string

    Returns:
        Normalized command
    """
    if not cmd:
        return ""

    # Trim and collapse whitespace only (preserve case)
    return " ".join(cmd.split())


# =============================================================================
# ANSI Escape Code Handling
# =============================================================================

# ANSI escape sequence pattern
# Matches color codes, cursor movement, and terminal control sequences
ANSI_PATTERN = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")


def strip_ansi(text: str) -> str:
    """
    Remove all ANSI escape sequences from text.

    Handles:
    - Color codes: \\x1b[31m (red), \\x1b[0m (reset)
    - Cursor movement: \\x1b[2J (clear screen)
    - Terminal control sequences

    Args:
        text: Text potentially containing ANSI codes

    Returns:
        Text with ANSI codes removed
    """
    return ANSI_PATTERN.sub("", text)


# =============================================================================
# Timestamp Normalization
# =============================================================================

# Common timestamp patterns to normalize
TIMESTAMP_PATTERNS = [
    re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:?\d{2})?"),  # ISO 8601
    re.compile(r"\d{2}:\d{2}:\d{2}"),  # HH:MM:SS
    re.compile(r"\[\d+\.\d+s\]"),  # Duration [1.23s]
]


def normalize_timestamps(text: str) -> str:
    """
    Replace common timestamp patterns with placeholder.

    This ensures that transcript hashes remain stable across runs
    even when timestamps differ.

    Args:
        text: Text potentially containing timestamps

    Returns:
        Text with timestamps replaced by [TIMESTAMP]
    """
    result = text
    for pattern in TIMESTAMP_PATTERNS:
        result = pattern.sub("[TIMESTAMP]", result)
    return result


# =============================================================================
# Transcript Normalization
# =============================================================================

# Maximum transcript length in bytes (10KB)
MAX_TRANSCRIPT_LENGTH = 10 * 1024


def normalize_transcript(transcript: str | None) -> str:
    """
    Normalize a terminal transcript for canonical hashing.

    Steps:
    1. Strip ANSI escape codes
    2. Normalize timestamps
    3. For each line: trim trailing whitespace, collapse internal whitespace
    4. Remove empty trailing lines
    5. Cap total length

    Args:
        transcript: Raw terminal transcript

    Returns:
        Normalized transcript
    """
    if not transcript:
        return ""

    # Strip ANSI codes first
    normalized = strip_ansi(transcript)

    # Normalize timestamps
    normalized = normalize_timestamps(normalized)

    # Process line by line
    lines = []
    for line in normalized.split("\n"):
        # Trim trailing whitespace
        processed = line.rstrip()
        # Collapse internal whitespace (tabs -> space, multiple spaces -> single)
        processed = re.sub(r"\t", " ", processed)
        processed = re.sub(r" +", " ", processed)
        lines.append(processed)

    # Remove empty trailing lines
    while lines and lines[-1] == "":
        lines.pop()

    # Join and cap length
    result = "\n".join(lines)
    if len(result) > MAX_TRANSCRIPT_LENGTH:
        result = result[:MAX_TRANSCRIPT_LENGTH]

    return result


# =============================================================================
# Path Normalization
# =============================================================================


def normalize_path(input_path: str | None) -> str:
    """
    Normalize a file system path for canonical hashing.

    Handles:
    - Home directory expansion (~ on Unix, %USERPROFILE% on Windows)
    - Resolution of . and ..
    - Conversion to absolute path
    - Lowercase drive letter on Windows

    Note: Symlink resolution is not performed (would require filesystem access).

    Args:
        input_path: Path to normalize

    Returns:
        Normalized absolute path in OS-native format
    """
    if not input_path:
        return ""

    normalized = input_path

    # Expand home directory (cross-platform)
    if normalized.startswith("~"):
        # Unix/macOS: ~/foo -> /Users/name/foo
        home = os.environ.get("HOME", "")
        normalized = normalized.replace("~", home, 1)
    elif "%USERPROFILE%" in normalized:
        # Windows: %USERPROFILE%\foo -> C:\Users\name\foo
        user_profile = os.environ.get("USERPROFILE", "")
        normalized = re.sub(r"%USERPROFILE%", user_profile, normalized, flags=re.IGNORECASE)

    # Resolve . and .. (uses OS-native separators)
    path_obj = Path(normalized)
    try:
        # Convert to absolute if relative
        if not path_obj.is_absolute():
            path_obj = Path.cwd() / path_obj
        # Resolve . and ..
        normalized = str(path_obj.resolve())
    except (OSError, ValueError):
        # If resolution fails, just normalize the path syntax
        normalized = os.path.normpath(normalized)

    # Windows: lowercase drive letter for consistency (C: -> c:)
    if sys.platform == "win32" and len(normalized) >= 2 and normalized[1] == ":":
        normalized = normalized[0].lower() + normalized[1:]

    return normalized


# =============================================================================
# Environment Variable Hashing
# =============================================================================

# Patterns that indicate an environment variable contains a secret
SECRET_PATTERNS = [
    re.compile(r"^(AWS_|AZURE_|GCP_|GOOGLE_)", re.IGNORECASE),  # Cloud providers
    re.compile(r"(_KEY|_SECRET|_TOKEN|_PASSWORD)$", re.IGNORECASE),  # Common suffixes
    re.compile(r"^(API_KEY|AUTH_TOKEN|PRIVATE_KEY)$", re.IGNORECASE),  # Common names
    re.compile(r"^(DATABASE_URL|REDIS_URL)$", re.IGNORECASE),  # Connection strings
]


def is_secret_key(key: str) -> bool:
    """
    Check if an environment variable key indicates a secret value.

    Args:
        key: Environment variable name

    Returns:
        True if the key matches a secret pattern
    """
    return any(p.search(key) for p in SECRET_PATTERNS)


def hash_environment(env: dict[str, str] | None) -> str:
    """
    Hash environment variables for canonical representation.

    - Redacts values for keys matching secret patterns
    - Sorts keys for determinism
    - Returns SHA-256 hash of canonical representation

    Args:
        env: Environment variables

    Returns:
        SHA-256 hash of canonical env representation
    """
    if not env:
        return sha256("")

    # Filter out secrets
    safe_env: dict[str, str] = {}
    for key, value in env.items():
        if is_secret_key(key):
            safe_env[key] = "[REDACTED]"
        else:
            safe_env[key] = value

    # Sort keys for determinism
    sorted_keys = sorted(safe_env.keys())
    canonical = "\n".join(f"{k}={safe_env[k]}" for k in sorted_keys)

    return sha256(canonical)


# =============================================================================
# Hashing
# =============================================================================


def sha256(input_str: str) -> str:
    """
    Compute SHA-256 hash of input string.

    Args:
        input_str: String to hash

    Returns:
        Hex-encoded SHA-256 hash
    """
    return hashlib.sha256(input_str.encode("utf-8")).hexdigest()


# =============================================================================
# Terminal Session Canonicalization
# =============================================================================

# Schema version for terminal canonicalization
TERMINAL_SCHEMA_VERSION = "terminal:v1.0"


@dataclass(frozen=True)
class CanonicalTerminalSnapshot:
    """Canonical terminal snapshot with normalized fields."""

    session_id: str
    terminal_id: str
    cwd_normalized: str
    command_normalized: str
    transcript_normalized: str
    exit_code: int | None
    env_hash: str
    platform: Platform


def detect_platform() -> Platform:
    """Detect the current platform."""
    platform = sys.platform
    if platform in ("darwin", "linux", "win32"):
        return platform  # type: ignore[return-value]
    # Default to linux for unknown Unix-like platforms
    return "linux"


def canonicalize_terminal_snapshot(snapshot: dict[str, Any]) -> CanonicalTerminalSnapshot:
    """
    Canonicalize a terminal session snapshot.

    Normalizes all fields to produce a deterministic representation:
    - cwd: Resolved to absolute path
    - command: Trimmed and whitespace-collapsed (case preserved)
    - transcript: ANSI stripped, timestamps normalized, whitespace collapsed
    - env: Sorted, secrets redacted, then hashed

    Args:
        snapshot: Raw terminal session snapshot dict

    Returns:
        Canonical snapshot for hashing
    """
    platform = snapshot.get("platform") or detect_platform()

    return CanonicalTerminalSnapshot(
        session_id=snapshot.get("session_id", ""),
        terminal_id=snapshot.get("terminal_id", "") or "",
        cwd_normalized=normalize_path(snapshot.get("cwd")),
        command_normalized=normalize_command(snapshot.get("command")),
        transcript_normalized=normalize_transcript(snapshot.get("transcript")),
        exit_code=snapshot.get("exit_code"),
        env_hash=hash_environment(snapshot.get("env")),
        platform=platform,
    )


def compute_terminal_state_hash(snapshot: dict[str, Any] | CanonicalTerminalSnapshot) -> str:
    """
    Compute state hash for a terminal session snapshot.

    The hash includes all canonical fields in a deterministic order.
    Platform is included because different platforms have different
    security contexts (e.g., Unix vs Windows permissions).

    Args:
        snapshot: Raw or canonical terminal snapshot

    Returns:
        SHA-256 hash prefixed with "sha256:"
    """
    # Canonicalize if not already canonical
    if isinstance(snapshot, CanonicalTerminalSnapshot):
        canonical = snapshot
    else:
        canonical = canonicalize_terminal_snapshot(snapshot)

    # Build deterministic JSON (sorted keys)
    hash_input = json.dumps(
        {
            "command_normalized": canonical.command_normalized,
            "cwd_normalized": canonical.cwd_normalized,
            "env_hash": canonical.env_hash,
            "exit_code": canonical.exit_code,
            "platform": canonical.platform,
            "session_id": canonical.session_id,
            "terminal_id": canonical.terminal_id,
            "transcript_normalized": canonical.transcript_normalized,
        },
        sort_keys=True,
    )

    return f"sha256:{sha256(hash_input)}"


# =============================================================================
# Desktop Accessibility Canonicalization
# =============================================================================

# Schema version for desktop canonicalization
DESKTOP_SCHEMA_VERSION = "desktop:v1.0"

# Maximum depth for UI tree canonicalization
MAX_TREE_DEPTH = 10

# Maximum children per node
MAX_CHILDREN_PER_NODE = 50

# Maximum length for window title
MAX_WINDOW_TITLE_LENGTH = 100


@dataclass(frozen=True)
class CanonicalAccessibilityNode:
    """Canonical accessibility node with normalized fields."""

    role: str
    name_norm: str
    children: tuple[CanonicalAccessibilityNode, ...]


@dataclass(frozen=True)
class CanonicalDesktopSnapshot:
    """Canonical desktop snapshot with normalized fields."""

    app_name_norm: str
    window_title_norm: str
    focused_path: str
    tree_hash: str
    platform: Platform


def canonicalize_accessibility_node(
    node: dict[str, Any] | None,
    depth: int = 0,
) -> CanonicalAccessibilityNode:
    """
    Canonicalize an accessibility tree node.

    Normalizes:
    - role: Lowercase, trimmed
    - name: Text normalization (whitespace, case, length)
    - children: Recursively canonicalized, sorted by (role, name)

    Ignores transient attributes: pid, position, focused, selected.

    Args:
        node: Raw accessibility node
        depth: Current depth (for truncation)

    Returns:
        Canonical node
    """
    if not node:
        return CanonicalAccessibilityNode(role="", name_norm="", children=())

    role = (node.get("role") or "").lower().strip()
    name_norm = normalize_text(node.get("name"))

    # Truncate at max depth
    if depth >= MAX_TREE_DEPTH:
        return CanonicalAccessibilityNode(role=role, name_norm=name_norm, children=())

    # Canonicalize children
    children: list[CanonicalAccessibilityNode] = []
    raw_children = node.get("children")
    if raw_children and isinstance(raw_children, list):
        # Limit children count
        limited_children = raw_children[:MAX_CHILDREN_PER_NODE]

        # Canonicalize each child
        children = [canonicalize_accessibility_node(child, depth + 1) for child in limited_children]

        # Sort children by (role, name_norm) for determinism
        children.sort(key=lambda c: (c.role, c.name_norm))

    return CanonicalAccessibilityNode(role=role, name_norm=name_norm, children=tuple(children))


def build_focused_path(focused_role: str | None = None, focused_name: str | None = None) -> str:
    """
    Build a focused element path string.

    Creates a path like "button[save]" representing the focused element.

    Args:
        focused_role: Role of the focused element
        focused_name: Name of the focused element

    Returns:
        Path string
    """
    role = (focused_role or "").lower().strip()
    name = normalize_text(focused_name)

    if not role and not name:
        return ""

    if not name:
        return role

    return f"{role}[{name}]"


def _canonical_node_to_dict(node: CanonicalAccessibilityNode) -> dict[str, Any]:
    """Convert canonical node to dict for JSON serialization."""
    return {
        "role": node.role,
        "name_norm": node.name_norm,
        "children": [_canonical_node_to_dict(c) for c in node.children],
    }


def canonicalize_desktop_snapshot(snapshot: dict[str, Any]) -> CanonicalDesktopSnapshot:
    """
    Canonicalize a desktop accessibility snapshot.

    Normalizes all fields to produce a deterministic representation:
    - app_name: Lowercase, trimmed
    - window_title: Text normalization (capped at 100 chars)
    - focused_path: Built from focused element info
    - tree_hash: SHA-256 of canonical tree JSON

    Args:
        snapshot: Raw desktop accessibility snapshot

    Returns:
        Canonical snapshot for hashing
    """
    platform = snapshot.get("platform") or detect_platform()

    # Canonicalize the UI tree if present
    if snapshot.get("ui_tree"):
        canonical_tree = canonicalize_accessibility_node(snapshot["ui_tree"])
        tree_hash = sha256(json.dumps(_canonical_node_to_dict(canonical_tree), sort_keys=True))
    elif snapshot.get("ui_tree_text"):
        # Fallback: hash the raw text if no structured tree
        tree_hash = sha256(normalize_text(snapshot["ui_tree_text"], 10000))
    else:
        tree_hash = sha256("")

    return CanonicalDesktopSnapshot(
        app_name_norm=normalize_text(snapshot.get("app_name")),
        window_title_norm=normalize_text(snapshot.get("window_title"), MAX_WINDOW_TITLE_LENGTH),
        focused_path=build_focused_path(snapshot.get("focused_role"), snapshot.get("focused_name")),
        tree_hash=tree_hash,
        platform=platform,
    )


def compute_desktop_state_hash(snapshot: dict[str, Any] | CanonicalDesktopSnapshot) -> str:
    """
    Compute state hash for a desktop accessibility snapshot.

    The hash includes all canonical fields in a deterministic order.
    Platform is included because different platforms have different
    accessibility APIs and security contexts.

    Args:
        snapshot: Raw or canonical desktop snapshot

    Returns:
        SHA-256 hash prefixed with "sha256:"
    """
    # Canonicalize if not already canonical
    if isinstance(snapshot, CanonicalDesktopSnapshot):
        canonical = snapshot
    else:
        canonical = canonicalize_desktop_snapshot(snapshot)

    # Build deterministic JSON (sorted keys)
    hash_input = json.dumps(
        {
            "app_name_norm": canonical.app_name_norm,
            "focused_path": canonical.focused_path,
            "platform": canonical.platform,
            "tree_hash": canonical.tree_hash,
            "window_title_norm": canonical.window_title_norm,
        },
        sort_keys=True,
    )

    return f"sha256:{sha256(hash_input)}"
