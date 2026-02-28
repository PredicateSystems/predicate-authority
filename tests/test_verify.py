"""Tests for post-execution verification module."""

from datetime import datetime, timedelta

from predicate_authority.verify import (
    ActualOperation,
    BrowserEvidence,
    CliEvidence,
    DbEvidence,
    FileEvidence,
    GenericEvidence,
    HttpEvidence,
    MandateDetails,
    VerificationFailureReason,
    Verifier,
    VerifyRequest,
    actions_match,
    get_evidence_type,
    normalize_resource,
    resources_match,
)


class TestNormalizeResource:
    """Tests for normalize_resource function."""

    def test_normalizes_filesystem_paths_multiple_slashes(self) -> None:
        assert normalize_resource("/src//index.ts") == "/src/index.ts"

    def test_normalizes_filesystem_paths_trailing_slash(self) -> None:
        assert normalize_resource("/src/") == "/src"

    def test_normalizes_filesystem_paths_dot_segments(self) -> None:
        assert normalize_resource("/src/./index.ts") == "/src/index.ts"

    def test_normalizes_url_like_resources(self) -> None:
        assert (
            normalize_resource("https://api.example.com//users") == "https://api.example.com/users"
        )
        assert (
            normalize_resource("https://api.example.com/users/") == "https://api.example.com/users"
        )

    def test_preserves_url_protocol(self) -> None:
        assert normalize_resource("https://api.example.com/path") == "https://api.example.com/path"


class TestResourcesMatch:
    """Tests for resources_match function."""

    def test_matches_identical_resources(self) -> None:
        assert resources_match("/src/index.ts", "/src/index.ts") is True

    def test_matches_after_normalization(self) -> None:
        assert resources_match("/src//index.ts", "/src/index.ts") is True
        assert resources_match("/src/index.ts", "/src//index.ts") is True

    def test_supports_glob_patterns_in_authorized_resource(self) -> None:
        assert resources_match("/src/*.ts", "/src/index.ts") is True
        assert resources_match("/src/**/*.ts", "/src/utils/helpers.ts") is True
        assert resources_match("/src/*.ts", "/src/index.js") is False

    def test_rejects_mismatched_resources(self) -> None:
        assert resources_match("/src/index.ts", "/src/main.ts") is False
        assert resources_match("/src/index.ts", "/lib/index.ts") is False

    def test_can_disable_glob_matching(self) -> None:
        assert resources_match("/src/*.ts", "/src/index.ts", allow_glob=False) is False


class TestActionsMatch:
    """Tests for actions_match function."""

    def test_matches_identical_actions(self) -> None:
        assert actions_match("fs.read", "fs.read") is True

    def test_handles_whitespace(self) -> None:
        assert actions_match("fs.read", " fs.read ") is True
        assert actions_match(" fs.read ", "fs.read") is True

    def test_supports_glob_patterns(self) -> None:
        assert actions_match("fs.*", "fs.read") is True
        assert actions_match("fs.*", "fs.write") is True
        assert actions_match("http.*", "fs.read") is False

    def test_is_case_sensitive(self) -> None:
        assert actions_match("fs.read", "fs.READ") is False


class TestVerifierVerifyLocal:
    """Tests for Verifier.verify_local method."""

    def setup_method(self) -> None:
        self.verifier = Verifier(base_url="http://127.0.0.1:8787")
        now = datetime.utcnow()
        self.base_mandate = MandateDetails(
            mandate_id="m_123",
            principal="agent:claude",
            action="fs.read",
            resource="/src/index.ts",
            intent_hash="ih_test",
            issued_at=now.isoformat() + "Z",
            expires_at=(now + timedelta(minutes=15)).isoformat() + "Z",
        )

    def test_verifies_matching_operation(self) -> None:
        request = VerifyRequest(
            mandate_id="m_123",
            actual=ActualOperation(
                action="fs.read",
                resource="/src/index.ts",
            ),
        )

        result = self.verifier.verify_local(self.base_mandate, request)
        assert result.verified is True
        assert result.reason is None

    def test_detects_action_mismatch(self) -> None:
        request = VerifyRequest(
            mandate_id="m_123",
            actual=ActualOperation(
                action="fs.write",  # Different action
                resource="/src/index.ts",
            ),
        )

        result = self.verifier.verify_local(self.base_mandate, request)
        assert result.verified is False
        assert result.reason == VerificationFailureReason.ACTION_MISMATCH
        assert result.authorized is not None
        assert result.authorized.action == "fs.read"
        assert result.actual is not None
        assert result.actual.action == "fs.write"

    def test_detects_resource_mismatch(self) -> None:
        request = VerifyRequest(
            mandate_id="m_123",
            actual=ActualOperation(
                action="fs.read",
                resource="/src/default.ts",  # Different resource
            ),
        )

        result = self.verifier.verify_local(self.base_mandate, request)
        assert result.verified is False
        assert result.reason == VerificationFailureReason.RESOURCE_MISMATCH
        assert result.authorized is not None
        assert result.authorized.resource == "/src/index.ts"
        assert result.actual is not None
        assert result.actual.resource == "/src/default.ts"

    def test_detects_expired_mandate(self) -> None:
        now = datetime.utcnow()
        expired_mandate = MandateDetails(
            mandate_id="m_123",
            principal="agent:claude",
            action="fs.read",
            resource="/src/index.ts",
            intent_hash="ih_test",
            issued_at=now.isoformat() + "Z",
            expires_at=(now - timedelta(seconds=1)).isoformat() + "Z",  # Expired
        )

        request = VerifyRequest(
            mandate_id="m_123",
            actual=ActualOperation(
                action="fs.read",
                resource="/src/index.ts",
            ),
        )

        result = self.verifier.verify_local(expired_mandate, request)
        assert result.verified is False
        assert result.reason == VerificationFailureReason.MANDATE_EXPIRED

    def test_supports_glob_patterns_in_mandate_resource(self) -> None:
        now = datetime.utcnow()
        glob_mandate = MandateDetails(
            mandate_id="m_123",
            principal="agent:claude",
            action="fs.read",
            resource="/src/*.ts",  # Glob pattern
            intent_hash="ih_test",
            issued_at=now.isoformat() + "Z",
            expires_at=(now + timedelta(minutes=15)).isoformat() + "Z",
        )

        request = VerifyRequest(
            mandate_id="m_123",
            actual=ActualOperation(
                action="fs.read",
                resource="/src/index.ts",
            ),
        )

        result = self.verifier.verify_local(glob_mandate, request)
        assert result.verified is True

    def test_supports_glob_patterns_in_mandate_action(self) -> None:
        now = datetime.utcnow()
        glob_mandate = MandateDetails(
            mandate_id="m_123",
            principal="agent:claude",
            action="fs.*",  # Glob pattern
            resource="/src/index.ts",
            intent_hash="ih_test",
            issued_at=now.isoformat() + "Z",
            expires_at=(now + timedelta(minutes=15)).isoformat() + "Z",
        )

        request = VerifyRequest(
            mandate_id="m_123",
            actual=ActualOperation(
                action="fs.read",
                resource="/src/index.ts",
            ),
        )

        result = self.verifier.verify_local(glob_mandate, request)
        assert result.verified is True


class TestVerificationEdgeCases:
    """Tests for edge cases in verification."""

    def setup_method(self) -> None:
        self.verifier = Verifier(base_url="http://127.0.0.1:8787")

    def test_handles_path_traversal_attempts(self) -> None:
        now = datetime.utcnow()
        mandate = MandateDetails(
            mandate_id="m_123",
            principal="agent:claude",
            action="fs.read",
            resource="/src/index.ts",
            intent_hash="ih_test",
            issued_at=now.isoformat() + "Z",
            expires_at=(now + timedelta(minutes=15)).isoformat() + "Z",
        )

        # Attempt to read a different file via path traversal
        request = VerifyRequest(
            mandate_id="m_123",
            actual=ActualOperation(
                action="fs.read",
                resource="/src/../etc/passwd",
            ),
        )

        result = self.verifier.verify_local(mandate, request)
        assert result.verified is False
        assert result.reason == VerificationFailureReason.RESOURCE_MISMATCH

    def test_handles_content_hash_in_actual_operation(self) -> None:
        now = datetime.utcnow()
        mandate = MandateDetails(
            mandate_id="m_123",
            principal="agent:claude",
            action="fs.read",
            resource="/src/index.ts",
            intent_hash="ih_test",
            issued_at=now.isoformat() + "Z",
            expires_at=(now + timedelta(minutes=15)).isoformat() + "Z",
        )

        request = VerifyRequest(
            mandate_id="m_123",
            actual=ActualOperation(
                action="fs.read",
                resource="/src/index.ts",
                content_hash="sha256:abc123...",
                executed_at=now.isoformat() + "Z",
            ),
        )

        result = self.verifier.verify_local(mandate, request)
        assert result.verified is True


class TestGetEvidenceType:
    """Tests for get_evidence_type function."""

    def test_returns_file_for_fs_actions(self) -> None:
        assert get_evidence_type("fs.read") == "file"
        assert get_evidence_type("fs.write") == "file"
        assert get_evidence_type("file.delete") == "file"

    def test_returns_cli_for_terminal_actions(self) -> None:
        assert get_evidence_type("cli.exec") == "cli"
        assert get_evidence_type("shell.run") == "cli"
        assert get_evidence_type("terminal.spawn") == "cli"

    def test_returns_browser_for_web_actions(self) -> None:
        assert get_evidence_type("browser.click") == "browser"
        assert get_evidence_type("browser.navigate") == "browser"
        assert get_evidence_type("web.scrape") == "browser"

    def test_returns_http_for_network_actions(self) -> None:
        assert get_evidence_type("http.get") == "http"
        assert get_evidence_type("http.post") == "http"
        assert get_evidence_type("https.request") == "http"

    def test_returns_db_for_database_actions(self) -> None:
        assert get_evidence_type("db.query") == "db"
        assert get_evidence_type("database.insert") == "db"
        assert get_evidence_type("sql.execute") == "db"

    def test_returns_generic_for_unknown_actions(self) -> None:
        assert get_evidence_type("custom.action") == "generic"
        assert get_evidence_type("unknown.operation") == "generic"


class TestEvidenceTypes:
    """Tests for discriminated union evidence types."""

    def test_file_evidence_has_correct_type(self) -> None:
        evidence = FileEvidence(
            type="file",
            action="fs.read",
            resource="/src/index.ts",
            content_hash="sha256:abc123",
        )
        assert evidence.type == "file"
        assert evidence.action == "fs.read"
        assert evidence.content_hash == "sha256:abc123"

    def test_cli_evidence_has_correct_type(self) -> None:
        evidence = CliEvidence(
            type="cli",
            action="cli.exec",
            resource="ls -la",
            exit_code=0,
            transcript_hash="sha256:def456",
        )
        assert evidence.type == "cli"
        assert evidence.exit_code == 0

    def test_browser_evidence_has_correct_type(self) -> None:
        evidence = BrowserEvidence(
            type="browser",
            action="browser.navigate",
            resource="https://example.com",
            final_url="https://example.com/redirected",
        )
        assert evidence.type == "browser"
        assert evidence.final_url == "https://example.com/redirected"

    def test_http_evidence_has_correct_type(self) -> None:
        evidence = HttpEvidence(
            type="http",
            action="http.get",
            resource="https://api.example.com/users",
            status_code=200,
            method="GET",
        )
        assert evidence.type == "http"
        assert evidence.status_code == 200

    def test_db_evidence_has_correct_type(self) -> None:
        evidence = DbEvidence(
            type="db",
            action="db.query",
            resource="users",
            rows_affected=5,
        )
        assert evidence.type == "db"
        assert evidence.rows_affected == 5

    def test_generic_evidence_has_correct_type(self) -> None:
        evidence = GenericEvidence(
            type="generic",
            action="custom.action",
            resource="some-resource",
            metadata={"key": "value"},
        )
        assert evidence.type == "generic"
        assert evidence.metadata == {"key": "value"}
