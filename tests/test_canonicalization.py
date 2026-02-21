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


class TestPhase4Verification:
    """Phase 4 verification tests for cross-platform, ANSI edge cases, and UI tree determinism."""

    class TestCrossPlatformPathNormalization:
        """Cross-platform path normalization tests."""

        def test_normalizes_unix_paths_with_dot_components(self) -> None:
            result = normalize_path("/home/user/./project/../project/src")
            assert "/." not in result
            assert "/.." not in result
            assert "project" in result
            assert "src" in result

        def test_handles_multiple_consecutive_slashes(self) -> None:
            result = normalize_path("/foo//bar///baz")
            assert "//" not in result

        def test_preserves_absolute_paths(self) -> None:
            result = normalize_path("/absolute/path/to/file")
            assert result.startswith("/")

        def test_handles_empty_path_components(self) -> None:
            result = normalize_path("/foo/./bar")
            assert result == "/foo/bar"

        def test_handles_trailing_slashes_consistently(self) -> None:
            with_slash = normalize_path("/foo/bar/")
            without_slash = normalize_path("/foo/bar")
            assert with_slash.rstrip("/") == without_slash.rstrip("/")

        def test_handles_root_path(self) -> None:
            result = normalize_path("/")
            assert result == "/"

    class TestAnsiStrippingEdgeCases:
        """ANSI stripping edge case tests."""

        def test_strips_256_color_codes(self) -> None:
            assert strip_ansi("\x1b[38;5;196mRed256\x1b[0m") == "Red256"
            assert strip_ansi("\x1b[48;5;21mBlueBg\x1b[0m") == "BlueBg"

        def test_strips_24bit_true_color_codes(self) -> None:
            assert strip_ansi("\x1b[38;2;255;100;50mOrange\x1b[0m") == "Orange"

        def test_strips_bold_italic_underline_codes(self) -> None:
            assert strip_ansi("\x1b[1mBold\x1b[0m") == "Bold"
            assert strip_ansi("\x1b[3mItalic\x1b[0m") == "Italic"
            assert strip_ansi("\x1b[4mUnderline\x1b[0m") == "Underline"

        def test_strips_cursor_movement_codes(self) -> None:
            assert strip_ansi("\x1b[5ACursor Up") == "Cursor Up"
            assert strip_ansi("\x1b[3BCursor Down") == "Cursor Down"
            assert strip_ansi("\x1b[2CCursor Forward") == "Cursor Forward"
            assert strip_ansi("\x1b[1DCursor Back") == "Cursor Back"

        def test_strips_erase_codes(self) -> None:
            assert strip_ansi("\x1b[2JClear Screen") == "Clear Screen"
            assert strip_ansi("\x1b[KClear Line") == "Clear Line"

        def test_strips_scroll_codes(self) -> None:
            assert strip_ansi("\x1b[3SScroll Up") == "Scroll Up"
            assert strip_ansi("\x1b[2TScroll Down") == "Scroll Down"

        def test_handles_multiple_ansi_codes_in_sequence(self) -> None:
            complex_text = "\x1b[1m\x1b[31m\x1b[4mBold Red Underline\x1b[0m"
            assert strip_ansi(complex_text) == "Bold Red Underline"

        def test_handles_ansi_codes_at_start_middle_and_end(self) -> None:
            text = "\x1b[32mStart\x1b[0m Middle \x1b[33mEnd\x1b[0m"
            assert strip_ansi(text) == "Start Middle End"

        def test_preserves_text_without_ansi_codes(self) -> None:
            plain = "No escape codes here: [not ansi] {also not}"
            assert strip_ansi(plain) == plain

    class TestUITreeDeterminism:
        """UI tree determinism tests."""

        def test_produces_same_hash_regardless_of_child_order(self) -> None:
            tree1 = {
                "role": "window",
                "name": "Main",
                "children": [
                    {"role": "button", "name": "Save", "children": []},
                    {"role": "button", "name": "Cancel", "children": []},
                    {"role": "textbox", "name": "Input", "children": []},
                ],
            }
            tree2 = {
                "role": "window",
                "name": "Main",
                "children": [
                    {"role": "textbox", "name": "Input", "children": []},
                    {"role": "button", "name": "Cancel", "children": []},
                    {"role": "button", "name": "Save", "children": []},
                ],
            }

            canonical1 = canonicalize_accessibility_node(tree1)
            canonical2 = canonicalize_accessibility_node(tree2)

            assert canonical1 == canonical2

        def test_normalizes_role_case(self) -> None:
            upper = canonicalize_accessibility_node(
                {"role": "BUTTON", "name": "Click", "children": []}
            )
            lower = canonicalize_accessibility_node(
                {"role": "button", "name": "Click", "children": []}
            )

            assert upper.role == lower.role
            assert upper.role == "button"

        def test_normalizes_name_whitespace_and_case(self) -> None:
            node1 = canonicalize_accessibility_node(
                {"role": "button", "name": "  Click   Me  ", "children": []}
            )
            node2 = canonicalize_accessibility_node(
                {"role": "button", "name": "click me", "children": []}
            )

            assert node1.name_norm == node2.name_norm
            assert node1.name_norm == "click me"

        def test_handles_empty_children_list(self) -> None:
            node = canonicalize_accessibility_node(
                {"role": "button", "name": "Test", "children": []}
            )
            assert node.children == ()

        def test_handles_missing_children(self) -> None:
            node = canonicalize_accessibility_node({"role": "button", "name": "Test"})
            assert node.children == ()

        def test_handles_none_name(self) -> None:
            node = canonicalize_accessibility_node({"role": "button", "name": None, "children": []})
            assert node.name_norm == ""

        def test_produces_identical_desktop_hashes_for_same_content(self) -> None:
            snap1 = {
                "app_name": "  FIREFOX  ",
                "window_title": "  GitHub - Pull Requests  ",
                "focused_role": "BUTTON",
                "focused_name": "  MERGE  ",
            }
            snap2 = {
                "app_name": "firefox",
                "window_title": "github - pull requests",
                "focused_role": "button",
                "focused_name": "merge",
            }

            assert compute_desktop_state_hash(snap1) == compute_desktop_state_hash(snap2)

        def test_sorts_nested_children_deterministically(self) -> None:
            tree = {
                "role": "window",
                "children": [
                    {
                        "role": "panel",
                        "name": "B",
                        "children": [
                            {"role": "button", "name": "Z", "children": []},
                            {"role": "button", "name": "A", "children": []},
                        ],
                    },
                    {
                        "role": "panel",
                        "name": "A",
                        "children": [
                            {"role": "link", "name": "Y", "children": []},
                            {"role": "link", "name": "X", "children": []},
                        ],
                    },
                ],
            }

            canonical = canonicalize_accessibility_node(tree)

            # First-level: panel A should come before panel B
            assert canonical.children[0].name_norm == "a"
            assert canonical.children[1].name_norm == "b"

            # Second-level: within panel A, link X should come before link Y
            assert canonical.children[0].children[0].name_norm == "x"
            assert canonical.children[0].children[1].name_norm == "y"

            # Within panel B, button A should come before button Z
            assert canonical.children[1].children[0].name_norm == "a"
            assert canonical.children[1].children[1].name_norm == "z"

    class TestTerminalHashStability:
        """Terminal hash stability tests."""

        def test_identical_hashes_for_varying_whitespace(self) -> None:
            snap1 = {"session_id": "s1", "command": "  npm   run   build  "}
            snap2 = {"session_id": "s1", "command": "npm run build"}

            assert compute_terminal_state_hash(snap1) == compute_terminal_state_hash(snap2)

        def test_identical_hashes_for_transcripts_with_ansi_removed(self) -> None:
            snap1 = {
                "session_id": "s1",
                "command": "test",
                "transcript": "\x1b[32m✓\x1b[0m Tests passed",
            }
            snap2 = {
                "session_id": "s1",
                "command": "test",
                "transcript": "✓ Tests passed",
            }

            assert compute_terminal_state_hash(snap1) == compute_terminal_state_hash(snap2)

        def test_different_hashes_for_different_commands(self) -> None:
            snap1 = {"session_id": "s1", "command": "npm install"}
            snap2 = {"session_id": "s1", "command": "npm update"}

            assert compute_terminal_state_hash(snap1) != compute_terminal_state_hash(snap2)

        def test_different_hashes_for_different_session_ids(self) -> None:
            snap1 = {"session_id": "session-1", "command": "test"}
            snap2 = {"session_id": "session-2", "command": "test"}

            assert compute_terminal_state_hash(snap1) != compute_terminal_state_hash(snap2)

        def test_handles_timestamps_in_transcripts(self) -> None:
            snap1 = {"session_id": "s1", "transcript": "Build completed at 10:30:45"}
            snap2 = {"session_id": "s1", "transcript": "Build completed at 14:22:01"}

            assert compute_terminal_state_hash(snap1) == compute_terminal_state_hash(snap2)
