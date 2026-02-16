# Caracal Codebase Overview (Agent Identity Focus)

## What This Project Is For

Caracal is a **pre-execution authority enforcement system** for AI agents and automated software.
Its core goal is to ensure actions are allowed **before execution**, not just audited after the fact.

In practical terms, Caracal sits between an agent and sensitive operations (API calls, tool use, data access) and enforces:

- a known principal identity,
- an active authority policy,
- a valid cryptographic execution mandate,
- and fail-closed behavior on uncertainty or errors.

The repository supports both:

- **Developer/operator interfaces** (`caracal` CLI and Python SDK), and
- **Enforcement runtime paths** (Gateway proxy and MCP adapter service).


## Overall Architecture and Key Components

Caracal is organized into several layers that map to identity, policy, enforcement, and audit.

### 1) Identity and Authority Domain (`caracal/core`, `caracal/db/models`)

- `core/identity.py`:
  - `AgentRegistry` manages identity lifecycle (`register`, `get`, `list`) with file persistence support.
  - Represents identities as `AgentIdentity` with optional parent-child hierarchy.
  - Can generate key pairs for delegation when integrated with token management.
- `db/models.py` (v0.5 schema):
  - `Principal`: canonical identity model (agent/user/service) with keys and optional parent.
  - `AuthorityPolicy`: per-principal constraints (allowed resources/actions, TTL limits, delegation depth).
  - `ExecutionMandate`: signed, time-bound authority grants with scopes and optional parent mandate.
  - `AuthorityLedgerEvent`: immutable record of issuance, validation, denial, revocation.

### 2) Cryptographic and Mandate Lifecycle (`caracal/core/crypto.py`, `core/mandate.py`, `core/authority.py`, `core/delegation.py`)

- `core/crypto.py`:
  - ECDSA P-256 signing and verification for mandates and Merkle roots.
  - Canonicalized JSON + SHA-256 for deterministic verification behavior.
- `core/mandate.py` (`MandateManager`):
  - Issues mandates after validating policy constraints and scope subset rules.
  - Supports delegation through parent mandates with depth and validity checks.
  - Supports revocation (with optional cascading down delegation chains).
- `core/authority.py` (`AuthorityEvaluator`):
  - Validates mandates at request time (signature, expiry, revocation, action/resource scope, delegation chain).
  - Implements explicit fail-closed semantics.
- `core/delegation.py` (`DelegationTokenManager`):
  - Generates and validates ASE-style JWT delegation tokens (ES256), tied to parent/child identities.

### 3) Enforcement Surfaces (`caracal/gateway`, `caracal/mcp`)

- `gateway/proxy.py`:
  - FastAPI reverse proxy for network-level enforcement.
  - Request flow: authenticate -> replay-check -> mandate validate -> forward -> meter -> respond.
  - Requires `X-Caracal-Mandate-ID` and `X-Caracal-Target-URL` headers for authority checks.
- `gateway/auth.py`:
  - Supports authentication via mTLS, JWT, or API key.
  - Maps successful auth to registered agent identity.
- `mcp/adapter.py`:
  - Intercepts MCP tool calls and resource reads.
  - Validates mandate against operation (`execute`/`read`) and target tool/resource.
  - Emits metering, with fail-closed denial on validation errors.
- `mcp/service.py`:
  - Standalone HTTP service wrapping MCP enforcement endpoints.

### 4) Ledger, Integrity, and Operations (`caracal/core/authority_ledger.py`, `caracal/merkle`, `caracal/monitoring`, `caracal/db`)

- `core/authority_ledger.py`:
  - Writes immutable authority events and supports filtered querying.
- `merkle/*`:
  - Cryptographic integrity pipeline (root signing, verification, snapshot/backfill/recovery paths).
- `db/connection.py` + migrations:
  - SQLAlchemy-based DB setup, pooling, session lifecycle, health checks, Alembic migrations.
- `monitoring/*`:
  - Health and metrics endpoints (Prometheus-compatible).

### 5) Interfaces and Experience Layers (`caracal/cli`, `caracal/sdk`, `caracal/flow`)

- `cli/main.py`:
  - Main entrypoint for administrative workflows (agents, policies, authority, ledger, db, mcp-service, etc.).
- `sdk/client.py`:
  - Programmatic interface for integration into applications/agent frameworks.
- `flow/main.py`:
  - `caracal-flow` interactive TUI for onboarding and operational management.


## How It Relates to Agent Identity

Agent identity is central to Caracal’s trust model. Identity is not just naming; it is a cryptographic and governance anchor.

### Identity Model

- Identity entities are represented as:
  - `AgentIdentity` in JSON/file-backed flows (legacy/developer workflows), and
  - `Principal` in DB-backed authority enforcement flows (v0.5 model).
- Principals can form parent-child hierarchies for delegated authority chains.

### Cryptographic Binding

- Mandates are signed by issuer private keys and verified using issuer public keys.
- Delegation tokens are also cryptographically signed (ES256), binding parent/child identity relationships.
- This means authority is both policy-constrained and cryptographically attestable.

### Policy-Bound Identity

- A principal’s allowed actions and resources are constrained by `AuthorityPolicy`.
- `MandateManager.issue_mandate()` enforces that issued scope/TTL/delegation depth stay within policy.
- Delegated mandates must be strict subsets of parent scope and validity windows.

### Runtime Enforcement with Identity Context

- Gateway and MCP adapter both require identity context + mandate.
- `AuthorityEvaluator.validate_mandate()` checks:
  - who issued the mandate,
  - who it authorizes (subject),
  - whether operation/resource is in scope,
  - whether chain and timing are valid.
- Any ambiguity/error defaults to denial (fail-closed).

### Identity-Centric Auditability

- Authority decisions are persisted to immutable authority ledger events keyed by principal/mandate.
- This creates a traceable chain of identity -> policy -> mandate -> decision.


## Main Entry Points and Workflows

## Runtime and CLI Entry Points

- Python package scripts (`pyproject.toml`):
  - `caracal` -> `caracal.cli.main:cli`
  - `caracal-flow` -> `caracal.flow.main:main`
- Additional service-style entry:
  - `caracal mcp-service start` (wraps MCP adapter HTTP service)
  - Gateway proxy is launched programmatically from `caracal.gateway.proxy.GatewayProxy`.

### Core Administrative Workflow

1. Register identity (`agent register` / principal creation path).
2. Define policy bounds (`policy create`).
3. Issue mandate (`authority issue`).
4. Use mandate at enforcement point (Gateway/MCP).
5. Validate or deny operation in real time (`AuthorityEvaluator`).
6. Persist authority decision to immutable authority ledger.
7. Revoke/rotate/delegate as needed (`authority revoke` / `authority delegate`).

### Gateway Enforcement Workflow

1. Receive request with auth credentials + Caracal headers.
2. Authenticate principal identity.
3. Check replay protection.
4. Load and validate mandate against action/resource.
5. If allowed, forward request; if denied, return fail-closed error.
6. Emit usage/metering and expose metrics/health for ops.

### MCP Enforcement Workflow

1. Intercept MCP call/read with context metadata.
2. Extract principal identity + mandate ID.
3. Validate mandate against tool or resource operation.
4. Execute/forward only if authorized.
5. Emit metering and authority outcomes.


## Architectural Notes and Observations

- The codebase currently shows a transition from **agent-centric v0.1/v0.2 models** to **principal-centric v0.5 authority models**. Both concepts coexist in parts of the repo.
- Enforcement logic consistently follows **fail-closed** principles across authority, gateway, and MCP adapters.
- The repository includes open-source stubs for enterprise-only modules (`caracal/enterprise`) while keeping core authority features available in OSS.
- Caracal supports both local/file-oriented workflows and production-oriented DB + service deployments, with compatibility modes for rollout.


## Direct Answers to Your Four Questions

1. **Main purpose**
   Caracal prevents unauthorized agent actions by enforcing cryptographically verifiable, time-bound authority *before* execution.

2. **Overall architecture and key components**
   It is layered around identity/principals, authority policies, signed mandates, runtime enforcement surfaces (Gateway/MCP), immutable authority ledgering, and operational tooling (CLI/SDK/TUI/monitoring).

3. **Relation to agent identity**
   Identity is foundational: mandates are issued to identities, signed by identities, validated against identity-bound policies, and audited per identity in an immutable ledger.

4. **Main entry points and workflows**
   Entry points are `caracal`, `caracal-flow`, and MCP/gateway services; workflows center on register -> policy -> issue mandate -> enforce at runtime -> log -> revoke/delegate.
