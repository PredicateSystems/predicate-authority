"""Tests for predicate_contracts.canonicalization module."""

from __future__ import annotations

from predicate_contracts.canonicalization import (  # Utility functions; Terminal canonicalization; Desktop canonicalization
    DESKTOP_SCHEMA_VERSION,
    TERMINAL_SCHEMA_VERSION,
    build_focused_path,
    canonicalize_accessibility_node,
    canonicalize_desktop_snapshot,
    canonicalize_terminal_snapshot,
    compute_desktop_state_hash,
    compute_terminal_state_hash,
    hash_environment,
    is_secret_key,
    normalize_command,
    normalize_path,
    normalize_text,
    normalize_timestamps,
    normalize_transcript,
    sha256,
    strip_ansi,
)


class TestNormalizeText:
    """Tests for normalize_text function."""

    def test_trims_and_collapses_whitespace(self) -> None:
        assert normalize_text("  Hello   World  ") == "hello world"

    def test_lowercases_text(self) -> None:
        assert normalize_text("HELLO") == "hello"

    def test_caps_length_at_max_len(self) -> None:
        long_text = "a" * 100
        assert len(normalize_text(long_text, 80)) == 80

    def test_returns_empty_for_none(self) -> None:
        assert normalize_text(None) == ""

    def test_returns_empty_for_empty_string(self) -> None:
        assert normalize_text("") == ""


class TestNormalizeCommand:
    """Tests for normalize_command function."""

    def test_trims_and_collapses_whitespace_preserves_case(self) -> None:
        assert normalize_command("  ls   -la  ") == "ls -la"
        assert normalize_command("  Git  Status  ") == "Git Status"

    def test_returns_empty_for_none(self) -> None:
        assert normalize_command(None) == ""


class TestStripAnsi:
    """Tests for strip_ansi function."""

    def test_removes_color_codes(self) -> None:
        assert strip_ansi("\x1b[31mRed\x1b[0m") == "Red"
        assert strip_ansi("\x1b[32mGreen\x1b[0m") == "Green"

    def test_removes_cursor_movement_codes(self) -> None:
        assert strip_ansi("\x1b[2JClear") == "Clear"

    def test_leaves_plain_text_unchanged(self) -> None:
        assert strip_ansi("Hello World") == "Hello World"


class TestNormalizeTimestamps:
    """Tests for normalize_timestamps function."""

    def test_replaces_iso8601_timestamps(self) -> None:
        assert normalize_timestamps("2024-01-15T10:30:45.123Z") == "[TIMESTAMP]"
        assert normalize_timestamps("2024-01-15 10:30:45") == "[TIMESTAMP]"

    def test_replaces_time_only_timestamps(self) -> None:
        assert normalize_timestamps("Started at 10:30:45") == "Started at [TIMESTAMP]"

    def test_replaces_duration_markers(self) -> None:
        assert normalize_timestamps("Completed [1.23s]") == "Completed [TIMESTAMP]"


class TestNormalizeTranscript:
    """Tests for normalize_transcript function."""

    def test_strips_ansi_and_normalizes_whitespace(self) -> None:
        raw = "\x1b[32mPASS\x1b[0m  test   suite"
        assert normalize_transcript(raw) == "PASS test suite"

    def test_normalizes_timestamps(self) -> None:
        raw = "Completed at 10:30:45"
        assert normalize_transcript(raw) == "Completed at [TIMESTAMP]"

    def test_removes_empty_trailing_lines(self) -> None:
        raw = "Line 1\nLine 2\n\n\n"
        assert normalize_transcript(raw) == "Line 1\nLine 2"

    def test_returns_empty_for_none(self) -> None:
        assert normalize_transcript(None) == ""

    def test_caps_length_at_10kb(self) -> None:
        huge = "x" * 20 * 1024
        assert len(normalize_transcript(huge)) <= 10 * 1024


class TestNormalizePath:
    """Tests for normalize_path function."""

    def test_resolves_dot_components(self) -> None:
        result = normalize_path("/foo/./bar/../baz")
        assert "/." not in result
        assert "/.." not in result

    def test_returns_empty_for_none(self) -> None:
        assert normalize_path(None) == ""


class TestIsSecretKey:
    """Tests for is_secret_key function."""

    def test_detects_cloud_provider_prefixes(self) -> None:
        assert is_secret_key("AWS_ACCESS_KEY_ID") is True
        assert is_secret_key("AZURE_CLIENT_SECRET") is True
        assert is_secret_key("GCP_SERVICE_ACCOUNT") is True
        assert is_secret_key("GOOGLE_APPLICATION_CREDENTIALS") is True

    def test_detects_common_secret_suffixes(self) -> None:
        assert is_secret_key("DATABASE_PASSWORD") is True
        assert is_secret_key("MY_SECRET") is True
        assert is_secret_key("AUTH_TOKEN") is True
        assert is_secret_key("PRIVATE_KEY") is True

    def test_allows_non_secret_keys(self) -> None:
        assert is_secret_key("HOME") is False
        assert is_secret_key("PATH") is False
        assert is_secret_key("NODE_ENV") is False


class TestHashEnvironment:
    """Tests for hash_environment function."""

    def test_returns_consistent_hash_for_same_env(self) -> None:
        env = {"HOME": "/home/user", "PATH": "/usr/bin"}
        hash1 = hash_environment(env)
        hash2 = hash_environment(env)
        assert hash1 == hash2

    def test_sorts_keys_for_determinism(self) -> None:
        env1 = {"B": "2", "A": "1"}
        env2 = {"A": "1", "B": "2"}
        assert hash_environment(env1) == hash_environment(env2)

    def test_redacts_secret_values(self) -> None:
        with_secret = {"AWS_ACCESS_KEY_ID": "secret123", "HOME": "/home"}
        with_redacted = {"AWS_ACCESS_KEY_ID": "[REDACTED]", "HOME": "/home"}
        assert hash_environment(with_secret) == hash_environment(with_redacted)

    def test_returns_hash_for_none(self) -> None:
        assert hash_environment(None) == sha256("")


class TestSha256:
    """Tests for sha256 function."""

    def test_produces_64_char_hex_hash(self) -> None:
        result = sha256("hello")
        assert len(result) == 64
        assert all(c in "0123456789abcdef" for c in result)

    def test_different_inputs_produce_different_hashes(self) -> None:
        assert sha256("hello") != sha256("world")


class TestTerminalCanonicalization:
    """Tests for terminal canonicalization functions."""

    def test_canonicalize_terminal_snapshot_normalizes_all_fields(self) -> None:
        raw = {
            "session_id": "sess-1",
            "cwd": "/tmp/./foo/../bar",
            "command": "  npm   test  ",
            "transcript": "\x1b[32mOK\x1b[0m  All tests passed at 10:30:45",
        }

        canonical = canonicalize_terminal_snapshot(raw)

        assert canonical.session_id == "sess-1"
        assert canonical.command_normalized == "npm test"
        assert "OK" in canonical.transcript_normalized
        assert "[TIMESTAMP]" in canonical.transcript_normalized
        assert "\x1b" not in canonical.transcript_normalized

    def test_compute_terminal_state_hash_produces_prefixed_hash(self) -> None:
        result = compute_terminal_state_hash(
            {
                "session_id": "sess-1",
                "command": "npm test",
            }
        )
        assert result.startswith("sha256:")
        assert len(result) == 7 + 64  # "sha256:" + 64 hex chars

    def test_equivalent_inputs_produce_identical_hashes(self) -> None:
        snap1 = {
            "session_id": "sess-1",
            "command": "  npm   test  ",
            "transcript": "\x1b[32mOK\x1b[0m",
        }
        snap2 = {
            "session_id": "sess-1",
            "command": "npm test",
            "transcript": "OK",
        }
        assert compute_terminal_state_hash(snap1) == compute_terminal_state_hash(snap2)

    def test_different_inputs_produce_different_hashes(self) -> None:
        snap1 = {"session_id": "sess-1", "command": "npm test"}
        snap2 = {"session_id": "sess-1", "command": "npm build"}
        assert compute_terminal_state_hash(snap1) != compute_terminal_state_hash(snap2)

    def test_exports_terminal_schema_version(self) -> None:
        assert TERMINAL_SCHEMA_VERSION == "terminal:v1.0"


class TestDesktopCanonicalization:
    """Tests for desktop canonicalization functions."""

    def test_canonicalize_accessibility_node_normalizes_role_and_name(self) -> None:
        node = canonicalize_accessibility_node(
            {
                "role": "BUTTON",
                "name": "  Click Me  ",
                "children": [],
            }
        )
        assert node.role == "button"
        assert node.name_norm == "click me"

    def test_canonicalize_accessibility_node_sorts_children(self) -> None:
        node = canonicalize_accessibility_node(
            {
                "role": "group",
                "children": [
                    {"role": "button", "name": "B"},
                    {"role": "button", "name": "A"},
                    {"role": "link", "name": "C"},
                ],
            }
        )
        assert node.children[0].name_norm == "a"
        assert node.children[1].name_norm == "b"
        assert node.children[2].name_norm == "c"

    def test_canonicalize_accessibility_node_truncates_at_max_depth(self) -> None:
        # Build a deeply nested tree
        deep_node: dict = {"role": "root", "children": []}
        current = deep_node
        for i in range(15):
            child: dict = {"role": f"level-{i}", "children": []}
            current["children"] = [child]
            current = child
        current["children"] = [{"role": "leaf", "children": []}]

        canonical = canonicalize_accessibility_node(deep_node)

        # Find the deepest non-empty level
        depth = 0
        node = canonical
        while node.children:
            depth += 1
            node = node.children[0]
        assert depth <= 10

    def test_build_focused_path_with_role_and_name(self) -> None:
        assert build_focused_path("button", "Save") == "button[save]"

    def test_build_focused_path_with_role_only(self) -> None:
        assert build_focused_path("button") == "button"

    def test_build_focused_path_with_nothing(self) -> None:
        assert build_focused_path() == ""

    def test_canonicalize_desktop_snapshot_normalizes_all_fields(self) -> None:
        raw = {
            "app_name": "  Firefox  ",
            "window_title": "  GitHub - Home  ",
            "focused_role": "BUTTON",
            "focused_name": "  Sign In  ",
        }

        canonical = canonicalize_desktop_snapshot(raw)

        assert canonical.app_name_norm == "firefox"
        assert canonical.window_title_norm == "github - home"
        assert canonical.focused_path == "button[sign in]"

    def test_compute_desktop_state_hash_produces_prefixed_hash(self) -> None:
        result = compute_desktop_state_hash(
            {
                "app_name": "Firefox",
                "window_title": "GitHub",
            }
        )
        assert result.startswith("sha256:")
        assert len(result) == 7 + 64

    def test_equivalent_inputs_produce_identical_hashes(self) -> None:
        snap1 = {
            "app_name": "  Firefox  ",
            "window_title": "  GitHub  ",
        }
        snap2 = {
            "app_name": "Firefox",
            "window_title": "GitHub",
        }
        assert compute_desktop_state_hash(snap1) == compute_desktop_state_hash(snap2)

    def test_exports_desktop_schema_version(self) -> None:
        assert DESKTOP_SCHEMA_VERSION == "desktop:v1.0"
