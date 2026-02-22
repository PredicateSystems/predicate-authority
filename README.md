# Predicate Authority

**Deterministic Authority for AI Agents: Secure the "Confused Deputy" with your existing Identity stack.**

[![License](https://img.shields.io/badge/License-MIT%2FApache--2.0-blue.svg)](LICENSE)
[![PyPI - predicate-authority](https://img.shields.io/pypi/v/predicate-authority.svg)](https://pypi.org/project/predicate-authority/)
[![PyPI - predicate-contracts](https://img.shields.io/pypi/v/predicate-contracts.svg)](https://pypi.org/project/predicate-contracts/)
[![Release Tag](https://img.shields.io/badge/release-vX.Y.Z-blue)](docs/pypi-release-guide.md)

<table>
<tr>
<td width="50%" align="center">
<strong>OpenClaw Agent Tool Calls</strong><br>
<video src="https://github.com/user-attachments/assets/0fdf1ebb-6044-4288-9613-cd46f98cc284" autoplay loop muted playsinline></video>
</td>
<td width="50%" align="center">
<strong>Temporal Workflows</strong><br>
<video src="https://github.com/user-attachments/assets/511b6d38-90ab-413e-8af6-a89fc459eea5" autoplay loop muted playsinline></video>
</td>
</tr>
</table>

`predicate-authority` is a production-grade pre-execution authority layer that binds AI agent identity to deterministic state. It bridges standard IdPs (Entra ID, Okta, OIDC) with runtime verification so every sensitive action is authorized, bounded, and provable.

## Why Predicate Authority?

Most agent security fails because it relies on static API keys or broad permissions. Predicate introduces short-lived mandates that are cryptographically tied to:

- `state_hash` (what state the agent is in),
- `intent_hash` (what action it intends to perform),
- policy constraints and required verification labels.

This closes the confused-deputy gap where an agent can misuse delegated credentials.

- **Bridge, don't replace**: leverage existing enterprise identity and governance.
- **Fail-closed by design**: deny before execution when state/intent/policy checks fail.
- **Deterministic binding**: authority is tied to runtime evidence, not only identity.
- **Provable controls**: each decision can emit signed proof events for audit pipelines.

### Why not just use IdP directly?

You should still use Entra/Okta/OIDC for identity and token issuance. `predicate-authority` adds the runtime control layer those systems do not provide by default for AI agents:

- pre-execution allow/deny checks right before each sensitive action,
- binding authority to current `state_hash` and `intent_hash`,
- optional required verification labels from runtime checks (currently web-agent only via [predicate-sdk](https://github.com/PredicateSystems/sdk-python) integration),
- fail-closed local enforcement and per-decision proof events.

In practice: IdP answers **who the principal is**, while `predicate-authority` answers **whether this exact action is allowed right now in this state**.

## Repository Components

| Package | Purpose |
| --- | --- |
| `predicate_contracts` | Shared typed contracts and protocols (`ActionRequest`, `PolicyRule`, evidence, decision/proof models). |
| `predicate_authority` | Runtime authorization engine (`PolicyEngine`, `ActionGuard`, mandate signing, proof ledger, telemetry emitter). |
| `examples/` | Browser/MCP/HTTP/sidecar examples for local and connected workflows. |

## Current Capabilities

Implemented in this repository:

- local pre-execution `ActionGuard.authorize(...)` and `enforce(...)`,
- signed local mandates with TTL (`LocalMandateSigner`),
- policy evaluation with deny precedence and required verification labels,
- typed [predicate-sdk](https://github.com/PredicateSystems/sdk-python) integration adapter (`predicate_authority.integrations`),
- OpenTelemetry-compatible trace emitter (`OpenTelemetryTraceEmitter`),
- pytest coverage for authorization, mandate, integration, and telemetry flows.

## Sidecar Prerequisite

This SDK requires the **Predicate Authority Sidecar** daemon to be running. The sidecar is a lightweight Rust binary that handles policy evaluation and mandate signing.

| Resource | Link |
|----------|------|
| Sidecar Repository | [predicate-authority-sidecar](https://github.com/PredicateSystems/predicate-authority-sidecar) |
| Download Binaries | [Latest Releases](https://github.com/PredicateSystems/predicate-authority-sidecar/releases) |
| License | MIT / Apache 2.0 |

### Quick Sidecar Setup

**Option A: Install with pip (recommended)**

```bash
# Install SDK with sidecar extra
pip install "predicate-authority[sidecar]"

# IMPORTANT: The binary is NOT downloaded automatically during pip install.
# You must manually download it:
predicate-download-sidecar

# The binary is installed to:
# - macOS: ~/Library/Application Support/predicate-authority/bin/predicate-authorityd
# - Linux: ~/.local/share/predicate-authority/bin/predicate-authorityd
# - Windows: %LOCALAPPDATA%/predicate-authority/bin/predicate-authorityd.exe
```

**Option B: Manual download**

```bash
# Download the latest release for your platform from GitHub:
# https://github.com/PredicateSystems/predicate-authority-sidecar/releases

# Extract and make executable
tar -xzf predicate-authorityd-darwin-arm64.tar.gz  # or your platform
chmod +x predicate-authorityd
```

### Running the Sidecar

The Rust sidecar uses **global CLI arguments** (before the `run` subcommand) or a **TOML config file**.

**CLI arguments (place BEFORE `run`):**

```bash
./predicate-authorityd \
  --host 127.0.0.1 \
  --port 8787 \
  --mode local_only \
  --policy-file policy.json \
  run
```

**Using environment variables:**

```bash
export PREDICATE_HOST=127.0.0.1
export PREDICATE_PORT=8787
export PREDICATE_MODE=local_only
export PREDICATE_POLICY_FILE=policy.json

./predicate-authorityd run
```

**Using a config file:**

```bash
# Generate example config
./predicate-authorityd init-config --output config.toml

# Run with config
./predicate-authorityd --config config.toml run
```

### Sidecar CLI Reference

```
GLOBAL OPTIONS (use before 'run'):
  -c, --config <FILE>           Path to TOML config file [env: PREDICATE_CONFIG]
      --host <HOST>             Host to bind to [env: PREDICATE_HOST] [default: 127.0.0.1]
      --port <PORT>             Port to bind to [env: PREDICATE_PORT] [default: 8787]
      --mode <MODE>             local_only or cloud_connected [env: PREDICATE_MODE]
      --policy-file <PATH>      Path to policy JSON [env: PREDICATE_POLICY_FILE]
      --identity-file <PATH>    Path to local identity registry [env: PREDICATE_IDENTITY_FILE]
      --log-level <LEVEL>       trace, debug, info, warn, error [env: PREDICATE_LOG_LEVEL]
      --control-plane-url <URL> Control-plane URL [env: PREDICATE_CONTROL_PLANE_URL]
      --tenant-id <ID>          Tenant ID [env: PREDICATE_TENANT_ID]
      --project-id <ID>         Project ID [env: PREDICATE_PROJECT_ID]
      --predicate-api-key <KEY> API key [env: PREDICATE_API_KEY]
      --sync-enabled            Enable control-plane sync [env: PREDICATE_SYNC_ENABLED]
      --fail-open               Fail open if control-plane unreachable [env: PREDICATE_FAIL_OPEN]

IDENTITY PROVIDER OPTIONS:
      --identity-mode <MODE>    local, local-idp, oidc, entra, or okta [env: PREDICATE_IDENTITY_MODE]
      --allow-local-fallback    Allow local/local-idp in cloud_connected mode
      --idp-token-ttl-s <SECS>  IdP token TTL seconds [default: 300]
      --mandate-ttl-s <SECS>    Mandate TTL seconds [default: 300]

LOCAL IDP OPTIONS (for identity-mode=local-idp):
      --local-idp-issuer <URL>  Issuer URL [env: LOCAL_IDP_ISSUER]
      --local-idp-audience <AUD> Audience [env: LOCAL_IDP_AUDIENCE]
      --local-idp-signing-key-env <VAR> Env var for signing key [default: LOCAL_IDP_SIGNING_KEY]

OIDC OPTIONS (for identity-mode=oidc):
      --oidc-issuer <URL>       Issuer URL [env: OIDC_ISSUER]
      --oidc-client-id <ID>     Client ID [env: OIDC_CLIENT_ID]
      --oidc-audience <AUD>     Audience [env: OIDC_AUDIENCE]

ENTRA OPTIONS (for identity-mode=entra):
      --entra-tenant-id <ID>    Tenant ID [env: ENTRA_TENANT_ID]
      --entra-client-id <ID>    Client ID [env: ENTRA_CLIENT_ID]
      --entra-audience <AUD>    Audience [env: ENTRA_AUDIENCE]

OKTA OPTIONS (for identity-mode=okta):
      --okta-issuer <URL>       Issuer URL [env: OKTA_ISSUER]
      --okta-client-id <ID>     Client ID [env: OKTA_CLIENT_ID]
      --okta-audience <AUD>     Audience [env: OKTA_AUDIENCE]
      --okta-required-claims    Required claims (comma-separated)
      --okta-required-scopes    Required scopes (comma-separated)
      --okta-required-roles     Required roles/groups (comma-separated)
      --okta-allowed-tenants    Allowed tenant IDs (comma-separated)

COMMANDS:
  run          Start the daemon (default)
  init-config  Generate example config file
  check-config Validate config file
  version      Show version info
```

### Identity Provider Modes

The sidecar supports multiple identity modes for token validation:

- **local** (default): No token validation. Suitable for development.
- **local-idp**: Self-issued JWT tokens for ephemeral task identities.
- **oidc**: Generic OIDC provider integration.
- **entra**: Microsoft Entra ID (Azure AD) integration.
- **okta**: Enterprise Okta integration with JWKS validation.

**Safety notes:**
- `idp-token-ttl-s` must be >= `mandate-ttl-s` (enforced at startup)
- In `cloud_connected` mode, `local` or `local-idp` requires `--allow-local-fallback`

For detailed IdP configuration and production hardening, see `docs/authorityd-operations.md`.

### Running the sidecar from Python

```python
from predicate_authority import run_sidecar, is_sidecar_available, download_sidecar

# Download if not available
if not is_sidecar_available():
    download_sidecar()

# Run sidecar as subprocess
process = run_sidecar(port=8787, policy_file="policy.json")

# Later: graceful shutdown
process.terminate()
process.wait()
```

## Installation

```bash
pip install predicate-authority

# Or with sidecar binary:
pip install predicate-authority[sidecar]
```

For local editable development in this monorepo, install both package roots
(do not use `pip install -e .` at repo root):

```bash
make dev-install
# equivalent: python -m pip install -e predicate_contracts -e predicate_authority
```

Release note: publish is supported by pushing a synchronized git tag `vX.Y.Z`
(see `docs/pypi-release-guide.md`).

For shared contracts directly:

```bash
pip install predicate-contracts
```

## Quick Start

```python
from predicate_authority import ActionGuard, InMemoryProofLedger, LocalMandateSigner, PolicyEngine
from predicate_contracts import (
    ActionRequest,
    ActionSpec,
    PolicyEffect,
    PolicyRule,
    PrincipalRef,
    StateEvidence,
    VerificationEvidence,
)

guard = ActionGuard(
    policy_engine=PolicyEngine(
        rules=(
            PolicyRule(
                name="allow-payment-submit",
                effect=PolicyEffect.ALLOW,
                principals=("agent:payments",),
                actions=("http.post",),
                resources=("https://finance.example.com/transfers",),
            ),
        )
    ),
    mandate_signer=LocalMandateSigner(secret_key="dev-secret"),
    proof_ledger=InMemoryProofLedger(),
)

request = ActionRequest(
    principal=PrincipalRef(principal_id="agent:payments"),
    action_spec=ActionSpec(
        action="http.post",
        resource="https://finance.example.com/transfers",
        intent="submit transfer request #1234",
    ),
    state_evidence=StateEvidence(source="backend", state_hash="state-hash-abc"),
    verification_evidence=VerificationEvidence(),
)

decision = guard.authorize(request)
if not decision.allowed:
    raise RuntimeError(f"Authority denied: {decision.reason.value}")
```

See runnable examples in:

- `examples/browser_guard_example.py`
- `examples/mcp_tool_guard_example.py`
- `examples/outbound_http_guard_example.py`

### Entra quick command (compatibility check)

```bash
set -a && source .env && set +a
python examples/delegation/entra_obo_compat_demo.py \
  --tenant-id "$ENTRA_TENANT_ID" \
  --client-id "$ENTRA_CLIENT_ID" \
  --client-secret "$ENTRA_CLIENT_SECRET" \
  --scope "$ENTRA_SCOPE"
```

### OIDC quick command (compatibility check)

```bash
set -a && source .env && set +a
python examples/delegation/oidc_compat_demo.py \
  --issuer "$OIDC_ISSUER" \
  --client-id "$OIDC_CLIENT_ID" \
  --client-secret "$OIDC_CLIENT_SECRET" \
  --audience "$OIDC_AUDIENCE" \
  --scope "${OIDC_SCOPE:-authority:check}"
```

### Cloud-connected sidecar (control-plane sync)

Connect the sidecar to Predicate Authority control-plane for policy sync, revocation push, and audit forwarding:

```bash
export PREDICATE_API_KEY="your-api-key"

./predicate-authorityd \
  --host 127.0.0.1 \
  --port 8787 \
  --mode cloud_connected \
  --policy-file policy.json \
  --control-plane-url https://api.predicatesystems.dev \
  --tenant-id your-tenant \
  --project-id your-project \
  --predicate-api-key "$PREDICATE_API_KEY" \
  --sync-enabled \
  run
```

## Sidecar Operations

### Ops docs quick links

- Sidecar operations guide: `docs/authorityd-operations.md`
- User manual (sync/integrity/operator behaviors): `docs/predicate-authority-user-manual.md`
- Control-plane production hardening runbook: `../predicate-authority-control-plane/docs/production-hardening-runbook.md`

### Sidecar health and status

```bash
curl http://127.0.0.1:8787/health
curl http://127.0.0.1:8787/status
```

### Policy reload

```bash
curl -X POST http://127.0.0.1:8787/policy/reload
```

### Revocation controls

```bash
curl -X POST http://127.0.0.1:8787/revoke/principal -d '{"principal_id": "agent:orders-01"}'
curl -X POST http://127.0.0.1:8787/revoke/intent -d '{"intent_hash": "<intent_hash>"}'
```


### Runtime endpoints

- `POST /v1/authorize` - Core authorization endpoint
- `GET /health` - Health check
- `GET /status` - Detailed status with metrics
- `POST /policy/reload` - Hot-reload policy
- `POST /revoke/principal` - Revoke by principal
- `POST /revoke/intent` - Revoke by intent hash
- `POST /revoke/mandate` - Revoke by mandate ID

## Security: Local Kill-Switch Path

`predicate-authority` supports fail-closed checks, local proof emission, and sidecar-managed revocation/token lifecycle for long-running agents.

## Release

- CI workflow: `.github/workflows/phase1-ci-and-release.yml`
- Release guide: `docs/pypi-release-guide.md`

Publish order is always:

1. `predicate-contracts`
2. `predicate-authority`

## Audit Vault and Control Plane

The Predicate sidecar and SDKs are 100% open-source and free for local development and single-agent deployments.

However, when deploying a fleet of AI agents in regulated environments (FinTech, Healthcare, Security), security teams cannot manage scattered YAML files or local SQLite databases. For production fleets, we offer the **Predicate Control Plane** and **Audit Vault**.

<table>
<tr>
<td width="50%" align="center">
<img src="docs/images/overview.png" alt="Control Plane Overview" width="100%">
<br><em>Real-time dashboard with authorization metrics</em>
</td>
<td width="50%" align="center">
<img src="docs/images/fleet_management.png" alt="Fleet Management" width="100%">
<br><em>Fleet management across all sidecars</em>
</td>
</tr>
<tr>
<td width="50%" align="center">
<img src="docs/images/audit_compliance.png" alt="Audit & Compliance" width="100%">
<br><em>WORM-ready audit ledger with 7-year retention</em>
</td>
<td width="50%" align="center">
<img src="docs/images/policies.png" alt="Policy Management" width="100%">
<br><em>Centralized policy editor</em>
</td>
</tr>
<tr>
<td width="50%" align="center">
<img src="docs/images/revocations.png" alt="Revocations" width="100%">
<br><em>Global kill-switches and revocations</em>
</td>
<td width="50%" align="center">
<img src="docs/images/siem_integrations.png" alt="SIEM Integrations" width="100%">
<br><em>SIEM integrations (Splunk, Datadog, Sentinel)</em>
</td>
</tr>
</table>

**Control Plane Features:**

* **Global Kill-Switches:** Instantly revoke a compromised agent's `principal` or `intent_hash`. The revocation syncs to all connected sidecars in milliseconds.
* **Immutable Audit Vault (WORM):** Every authorized mandate and blocked action is cryptographically signed and stored in a 7-year, WORM-ready ledger. Prove to SOC2 auditors exactly *what* your agents did and *why* they were authorized.
* **Fleet Management:** Manage your fleet of agents with total control
* **SIEM Integrations:** Stream authorization events and security alerts directly to Datadog, Splunk, or your existing security dashboard.
* **Centralized Policy Management:** Update and publish access policies across your entire fleet without redeploying agent code.

**[Learn more about Predicate Systems](https://www.predicatesystems.ai)**

---

## License

Dual-licensed under **MIT** and **Apache 2.0**:

- `LICENSE-MIT`
- `LICENSE-APACHE`

---

Copyright (c) 2026 Predicate Systems Inc.
