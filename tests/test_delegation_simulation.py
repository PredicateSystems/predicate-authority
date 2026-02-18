from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


def test_delegate_worker_revocation_blocks_worker(tmp_path: Path) -> None:
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text(
        "\n".join(
            [
                "rules:",
                "  - name: allow-delegate-task",
                "    effect: allow",
                "    principals:",
                "      - agent:root",
                "    actions:",
                "      - task.delegate",
                "    resources:",
                "      - worker:queue/*",
                "    max_delegation_depth: 1",
                "  - name: allow-worker-execute",
                "    effect: allow",
                "    principals:",
                "      - agent:worker",
                "    actions:",
                "      - job.execute",
                "    resources:",
                "      - queue://jobs/*",
                "    max_delegation_depth: 1",
            ]
        ),
        encoding="utf-8",
    )
    revocation_file = tmp_path / "revocations.json"

    repo_root = Path(__file__).resolve().parents[1]
    delegate_script = repo_root / "examples" / "delegation" / "delegate.py"
    worker_script = repo_root / "examples" / "delegation" / "worker.py"

    command = [
        sys.executable,
        str(delegate_script),
        "--policy-file",
        str(policy_file),
        "--worker-script",
        str(worker_script),
        "--revocation-file",
        str(revocation_file),
        "--secret-key",
        "delegation-test-secret",
    ]
    result = subprocess.run(command, check=True, capture_output=True, text=True)  # noqa: S603
    payload = json.loads(result.stdout)

    assert payload["root_allowed"] is True
    assert payload["root_delegation_depth"] == 0
    assert payload["worker_allowed_before_revoke"] is True
    assert payload["worker_delegation_depth_before_revoke"] == 1
    assert payload["worker_chain_verified_before_revoke"] is True
    assert payload["worker_allowed_after_revoke"] is False
    assert payload["after_reason"] == "revoked_root_token"
