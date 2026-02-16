# Better SDK Opportunity Proposal

## Goal

Design a new SDK that gives Predicate a **production-grade pre-execution authority enforcement layer** for AI agents, while integrating with existing enterprise identity systems and preserving the deterministic guarantees already provided by `sdk-python`.

Important scope note:

- `sdk-python` is web-agent specific because it depends on a Playwright/page snapshot engine.
- Non-web agents (backend/code/infra agents) cannot directly use `sdk-python` snapshot verification and must use a runtime-agnostic authority path in `predicate-authority` (policy, mandate, intent, and proof checks without page snapshots).

This proposal answers the "Better SDK Opportunity" in `northstar.md` by combining:

- Predicate's deterministic verification runtime (`assert_`, `check().eventually()`, `assert_done`, traces, artifacts),
- Caracal's strongest ideas (short-lived mandates, scope checks, fail-closed gateway-style enforcement, immutable authority ledger),
- A bridge-first strategy (works with Azure AD/Okta/Auth0 and existing agent stacks).

## Progress Dashboard

Status snapshot date: 2026-02-16

| Phase | Status | ETA | Owner |
| --- | --- | --- | --- |
| Phase 0: Architecture and Spec Lock | Partially complete | 1-2 weeks total (remaining: sign-off + schema/process formalization) | SDK + Platform + Security |
| Phase 1: Local SDK Guard (MVP) | In progress | 3-5 weeks total (remaining: `sdk-python` hooks + OTel export + examples + CI publish flow) | SDK |
| Phase 2: Sidecar + Identity Bridge | Not started (design only) | 4-6 weeks | Platform + Identity |
| Phase 3: Hosted Governance Control Plane | Not started (design only) | 6-8 weeks | Platform + Product |
| Phase 4: Enterprise Hardening and Scale | Not started (design only) | Ongoing (first 4-6 weeks) | Platform + Security + GTM |


## TL;DR Design

Build a new package family centered on:

- `predicate-authority` (Python)
- optional sidecar `predicate-authorityd` (local authority broker)

Core behavior:

1. Agent asks for authority **before** sensitive action.
2. SDK binds request to deterministic state (snapshot hash, step id, run id, assertion outcomes).
3. Authority is issued as a short-lived capability/mandate token with strict scope.
4. Enforcement wrappers verify token + scope + state constraints before executing action.
5. Every decision is logged with cryptographic proofs for audit and replay.
6. Any uncertainty/failure => fail closed (no action).


## Why This Is Better (vs Caracal-only or verification-only)

- **Vs verification-only (`sdk-python`)**: adds true "can/cannot execute" authorization, not just "did it work?" checks.
- **Vs Caracal-only**: keeps deterministic runtime deeply coupled to authorization and integrates with enterprise IdPs instead of requiring a parallel identity silo.
- **Enterprise fit**: supports existing identity/SSO and logging systems (Splunk/Datadog/SIEM) plus cryptographic proof records.


## Product Surface

## 1) Python SDK (`predicate_authority`)

Main components:

- `AuthorityClient`: obtains/revokes short-lived mandates.
- `ActionGuard`: pre-execution check for tool/API/browser actions.
- `IdentityBridge`: adapter for IdPs (Entra/Okta/Auth0/custom OIDC).
- `ProofLedger`: signed decision/event writer.
- `PolicyEngine`: evaluates local+remote policy constraints.

## 2) Sidecar (`predicate-authorityd`) - recommended for production

A local daemon (`localhost`) that:

- stores and rotates refresh credentials safely,
- mints/refreshes short-lived mandates,
- enforces local policy and deterministic invariants before refresh/issue,
- allows token revocation/kill-switch without app restart.

This follows the "cached credentials service" operational model and is ideal for long-running agents.

## 3) Optional control plane

Central policy/authority service for:

- policy management,
- mandate issuance delegation,
- revocation propagation,
- audit aggregation.

The SDK can run in local-only mode or connected mode.

## 4) Business model plane (hosted governance)

Keep the SDK open source (MIT/Apache-2.0), monetize the connected governance plane:

- hosted audit and retention,
- centralized policy orchestration,
- fleet-wide revocation and incident controls,
- enterprise identity/compliance operations.


## Integration with Existing `sdk-python`

The new SDK should be additive and compose with `AgentRuntime` rather than replacing it.

Constraint:

- this integration applies to web agents where `AgentRuntime` and page snapshots are available.
- non-web agents integrate through `predicate-authority` directly (SDK guard + sidecar + IdentityBridge) without `sdk-python` dependencies.

## Hook points in current runtime flow

At each sensitive step:

1. `runtime.begin_step(...)`
2. `await runtime.snapshot()`
3. deterministic checks (`assert_`/`check`)
4. **new: `guard.authorize(...)` before action**
5. execute action
6. post-condition verify (`assert_`)
7. emit traces and ledger proofs

This creates two gates:

- **Pre-execution authority gate**: "Are you allowed to try this?"
- **Post-execution deterministic gate**: "Did the intended effect occur?"

Both are required for production trust.

## Suggested Python usage

```python
from predicate import AgentRuntime
from predicate_authority import AuthorityClient, ActionGuard, ActionSpec

runtime = AgentRuntime.from_playwright_page(page, tracer=tracer)
auth = AuthorityClient.from_env()          # bridge to sidecar or control plane
guard = ActionGuard(runtime=runtime, authority_client=auth)

runtime.begin_step("checkout_submit")
await runtime.snapshot()

# Deterministic precondition from existing sdk-python
runtime.assert_(exists("role=button text~'Submit'"), "submit_present", required=True)

# New authority pre-execution gate
decision = await guard.authorize(
    ActionSpec(
        action="web.click",
        resource="https://shop.example.com/checkout#submit",
        tool="playwright.click",
        risk_level="high",
    ),
    required_predicates=["submit_present"],
)

if not decision.allowed:
    raise RuntimeError(f"Blocked by authority: {decision.reason}")

await page.click("role=button text~'Submit'")
await runtime.snapshot()

# Existing deterministic postcondition
runtime.assert_(exists("text~'Order Confirmed'"), "order_confirmed", required=True)
await runtime.emit_step_end()
```


## Authorization Model

Use short-lived **Execution Mandates** (capability tokens) with explicit constraints:

- `sub`: agent/principal identity
- `iss`: authority issuer (sidecar/control plane)
- `aud`: target system/tool class
- `exp`: very short TTL (e.g., 30-120s)
- `action_scope`: verbs (`web.click`, `mcp.execute`, `http.post`, etc.)
- `resource_scope`: URL/tool/resource patterns
- `budget_scope`: optional spend/quota constraints
- `delegation_depth`: bounded chain
- `intent_hash`: hash of requested action intent
- `state_hash`: hash of relevant deterministic state snapshot
- `run_id`, `step_id`, `correlation_id`

Mandates are cryptographically signed (ES256/EdDSA) and locally verifiable.


## Determinism + Authority Binding (Key Innovation)

Caracal validates mandate + scope. Predicate validates effect deterministically.
The new SDK should cryptographically bind those two worlds:

- **State-bound mandate issuance**: include `state_hash` from latest snapshot/assertion context.
- **Predicate-bound authority**: require specified verification labels to pass before issuance.
- **Intent-bound mandate**: include canonical action payload hash (`intent_hash`) to prevent replay/mutation.

This ensures "authorized" means:

1. right identity,
2. right scope,
3. right time,
4. right state context,
5. right exact action.

## Interface Decision: State Hash and Verification Signals

Based on review of `sdk-python/predicate/snapshot.py` and `sdk-python/predicate/backends/snapshot.py`:

- those modules provide snapshot collection (extension/API/backend-agnostic paths),
- they do **not** currently expose a first-class interface contract for `state_hash`,
- current runtime digesting patterns should be treated as implementation detail, not a cross-SDK contract.

Design decision:

- introduce an explicit authority-facing interface layer in a tiny shared package: `predicate-contracts`,
- have `sdk-python` and `predicate-authority` both depend on `predicate-contracts`,
- provide non-web adapters with equivalent contracts that do not depend on browser snapshots.

### Package dependency graph (one-way)

To avoid import cycles, use this package layout:

- `predicate-contracts` (tiny shared package)
  - only Protocols + data contracts (`StateEvidence`, `VerificationSignal`, etc.)
  - no runtime dependencies on Playwright, `sdk-python`, or authority services
- `predicate-authority`
  - depends on `predicate-contracts`
  - authority logic, policy engine, sidecar client, mandate handling
- `sdk-python`
  - depends on `predicate-contracts`
  - implements web-specific evidence adapters against existing `AgentRuntime`
- optional integration package: `predicate-authority-sdk-python-adapter`
  - depends on both `predicate-authority` and `sdk-python`
  - keeps cross-package glue isolated

Graph:

```text
predicate-contracts
   ├──> predicate-authority
   ├──> sdk-python
   └──> predicate-authority-sdk-python-adapter (optional, also depends on the two above)
```

### Release pipeline impact (PyPI)

Because `predicate-authority` depends on `predicate-contracts`, release automation must publish both packages with ordering control.

Required pipeline behavior:

1. Build/test/publish `predicate-contracts` first.
2. Wait for package availability on PyPI.
3. Build/test/publish `predicate-authority` pinned to the new compatible `predicate-contracts` version range.
4. (Optional) Build/test/publish `predicate-authority-sdk-python-adapter`.

Recommended controls:

- semantic versioning for `predicate-contracts` with strict compatibility rules,
- CI guard that blocks `predicate-authority` publish if required `predicate-contracts` version is unavailable,
- contract-compat test matrix (`sdk-python` x `predicate-authority` against targeted `predicate-contracts` versions),
- synchronized release notes for contract changes.

### 1) `StateEvidenceProvider` interface (new)

Purpose: normalize state capture into a signed/hashable evidence object across web and non-web agents.

Proposed contract:

```python
class StateEvidenceProvider(Protocol):
    async def capture_state_evidence(self) -> "StateEvidence":
        ...
```

```python
@dataclass
class StateEvidence:
    source_type: Literal["web_snapshot", "task_context", "tool_context", "infra_context"]
    state_hash: str | None
    state_schema_version: str
    captured_at_ms: int
    confidence: float | None
    refs: dict[str, str]          # trace_id, step_id, snapshot_id, run_id
    attributes: dict[str, Any]    # optional lightweight canonical fields
```

Notes:

- `state_hash` is optional at interface level (for backward compatibility), but strongly recommended in production policy.
- for web agents, compute `state_hash` from canonicalized snapshot fields (stable sort + selected fields), not raw timestamps.
- for non-web agents, compute `state_hash` from canonical task/tool context (intent payload hash, target resource, dependency versions, execution environment fingerprint).

### 2) `VerificationEvidenceProvider` interface (new)

Purpose: formalize what "verification labels passed" means beyond boolean shortcuts.

Proposed contract:

```python
class VerificationEvidenceProvider(Protocol):
    def get_verification_evidence(self) -> "VerificationEvidence":
        ...
```

```python
@dataclass
class VerificationSignal:
    label: str
    status: Literal["passed", "failed", "error", "unknown"]
    required: bool
    reason: str
    details: dict[str, Any]
    observed_at_ms: int

@dataclass
class VerificationEvidence:
    signals: list[VerificationSignal]
    summary: dict[str, Any]  # required_passed, failed_labels, signal_count
```

Key clarification:

- verification labels are **not** just `true/false`; they are named assertions with status + reason + details.
- authorization policies should evaluate predicates over this richer signal set, for example:
  - required labels must be `passed`,
  - specific labels may allow `passed` or `unknown` in dry-run mode,
  - any `error` on critical labels causes fail-closed deny.

### Web adapter mapping (from `sdk-python`)

- map existing runtime assertion records (`label`, `passed`, `required`, `reason`, `details`) into `VerificationSignal`.
- derive web `StateEvidence` from latest snapshot/assertion context.
- keep this mapping in an adapter module (do not hardwire authority logic into snapshot modules).

### Non-web adapter mapping

- generate `VerificationSignal` from deterministic checks available in that runtime (API response contracts, schema validators, policy checks, build/deploy preconditions).
- generate `StateEvidence` from canonical execution context (no Playwright dependency).

### Policy implications

- make `state_hash` policy-configurable:
  - `required_for_actions`: list of high-risk actions requiring non-null `state_hash`.
  - `accepted_source_types`: permitted evidence source types per action class.
- keep fail-closed default:
  - if policy requires evidence and provider cannot produce it, deny.


## Identity Bridge Strategy (Enterprise-Friendly)

Do not force a new IdP. Bridge existing enterprise identity.

## `IdentityBridge` adapters

- `EntraBridge` (MSAL/OIDC),
- `OktaBridge`,
- generic `OIDCBridge`.

Flow:

1. Get enterprise token (OIDC/OAuth standard).
2. Exchange for Predicate mandate (or embed signed context assertion).
3. Use mandate for pre-exec enforcement.
4. On invariant violation, revoke local capability and optionally signal upstream revocation.

This mirrors familiar OBO/delegation patterns while keeping Predicate-specific context enforcement.


## Enforcement Planes

Support three enforcement planes from day one:

1. **In-process SDK guard**
   - easiest adoption; wraps tool/API/browser actions directly.

2. **Gateway mode** (HTTP/tool proxy)
   - policy enforcement at network boundary (Caracal-style PEP).

3. **Sidecar authority broker**
   - secure token lifecycle + local kill switch + cached credentials handling.

All three should share the same policy and decision schema.


## Policy Model (v1)

Policy should be explicit and composable:

- principal policy (who),
- action/resource policy (what),
- temporal policy (when),
- budget policy (how much),
- state invariant policy (in which deterministic state),
- delegation policy (how deep / from whom).

Example policy snippet:

```yaml
principal: agent:checkout-bot
allow:
  - action: web.click
    resource: https://shop.example.com/checkout*
    requires:
      predicates_passed: [submit_present, cart_nonempty]
      max_age_seconds: 15
      risk_level: [medium, high]
limits:
  max_delegation_depth: 1
  mandate_ttl_seconds: 60
  budget_usd_per_run: 100
deny_by_default: true
```


## Audit and Proof Ledger

For each decision, emit:

- normalized decision event,
- canonical payload hash,
- signature/proof envelope,
- links to trace/snapshot/artifacts from `sdk-python`.

Store in:

- customer SIEM/log infra (Splunk/Datadog/OpenTelemetry), and optionally
- a tamper-evident append-only proof store.

This avoids "must use our DB" while preserving cryptographic accountability.

## Monetization Design (Open Core, Hosted Governance)

Revenue model principle:

- **Do not charge for the SDK lock.**
- **Charge for the cloud governance system of record.**

This works especially well for non-web agents that cannot use Snapshot Engine but still need high-volume authority checks.

## Unified Credit Model

Rebrand "Snapshot Credits" to **Verification Credits** so one credit system covers hybrid fleets.

| Action Type | Product Used | Cost per Action | Why |
| --- | --- | --- | --- |
| Visual Verification | Snapshot Engine (web agents) | 10 credits | Higher GPU/CV compute and higher per-step diagnostic value |
| Authority Check | Identity/Authority SDK (non-web + web) | 1 credit | Lower crypto/policy compute, much higher request volume |

Implication: one subscription can serve mixed fleets (web, backend, code, infra agents) without separate billing products.

## Monetization Hooks

## 1) Audit Vault (Compliance as a Service)

- Problem: local sidecar logs are not sufficient for regulated audit retention.
- Product: SDK/sidecar pushes signed proof events to Predicate Cloud Audit Vault.
- Monetization: by event volume + retention tier (30 days, 1 year, 7 years/WORM).
- Value proposition: "SDK enforces policy; cloud proves compliance."

## 2) Command Center (Fleet Management)

- Problem: policy changes across hundreds of sidecars are operationally expensive.
- Product: centralized policy dashboard + near-real-time policy sync.
- Monetization: Teams/Enterprise feature gating, with seat or org-based base + volume overage.

## 3) Global Kill-Switch (Security)

- Problem: compromised key/principal/intent requires immediate coordinated revocation.
- Product: revoke by `principal_id`, `intent_hash`, `mandate lineage`, or policy tag globally.
- Runtime behavior: sidecars poll/stream revocation updates (for example every 30 seconds or push channel).
- Monetization: Enterprise security control.

## Suggested Pricing Shape (Web + Identity)

| Tier | Pricing | Identity / Authority Features | Snapshot Features |
| --- | --- | --- | --- |
| Hobby | Free | Local mode only: local sidecar, local YAML policy, no cloud audit log | 500 credits/month |
| Pro | $XX/month | Connected mode: 30-day cloud audit log, 50,000 authority checks (50,000 credits), basic policy sync | 5,000 credits/month |
| Teams | $XXX/month | Fleet management: centralized policy dashboard, global kill-switch, unlimited active agents (volume billed) | 20,000 credits/month |
| Enterprise | Custom | Compliance + SSO: 7-year Audit Vault (WORM), managed Entra/Okta bridge, SLA/support | Volume discounts |

Notes:

- Keep credit burn transparent in SDK telemetry (`credits_spent`, `credits_estimate`) so customers can forecast.
- Offer pooled org credits so hybrid agent teams can allocate credits dynamically.
- Add overage pricing bands to avoid hard stops for production workloads.

## Why this monetizes non-web agents well

- **Backend agents (high call volume):** burn low-cost authority credits at scale; strong usage revenue.
- **Infra/ops agents (lower volume, high risk):** buy Audit Vault + kill-switch + retention for governance/compliance.
- **Code agents:** often run in CI/CD and need deterministic authority trails; high fit for policy sync and revocation.

## Commercial positioning

- **Free:** the lock (SDK + local enforcement).
- **Paid:** the security camera and command center (Audit Vault + policy orchestration + kill-switch).
- **Strategic message:** Predicate is the **System of Record for Agent Authority**, not just an SDK toolkit.


## SDK API Proposal (v1)

Primary API surfaces:

- `AuthorityClient.request_mandate(action_spec, context)`
- `ActionGuard.authorize(action_spec, required_predicates=...)`
- `ActionGuard.enforce(action_callable, action_spec, postcondition=...)`
- `ProofLedger.record(decision, trace_refs, artifact_refs)`
- `IdentityBridge.exchange_token(subject, context_assertion)`

Optional decorator form:

```python
@guard.protected(action="mcp.execute", resource="mcp://tools/web_search")
async def web_search_tool(query: str):
    ...
```


## Rollout Plan

## Phase 1: SDK-only guard (2-4 weeks)

- In-process pre-exec gate.
- Signed local mandates.
- Basic policy DSL.
- Trace/proof event emission to existing tracer.

Status (as of 2026-02-16): **in progress (MVP scaffold implemented in this `predicate-authority` repository)**

- Completed in repo:
  - `predicate-contracts` package scaffold with typed contracts and protocols.
  - `predicate-authority` local `ActionGuard.authorize(...)` + `enforce(...)`.
  - Signed local mandates with TTL + verification.
  - Local policy evaluation and normalized deny reasons.
  - In-memory proof ledger with optional trace emitter interface.
  - pytest coverage for policy, mandate signing, and proof emission paths.
- Pending for full Phase 1 exit:
  - direct `sdk-python` integration hooks (pre-action + postcondition linkage),
  - OpenTelemetry-native event export (beyond protocol-level trace emitter),
  - developer quickstart/examples for browser/MCP/HTTP guard patterns,
  - package publishing pipeline verification (`predicate-contracts` -> `predicate-authority`).

## Phase 2: Sidecar and IdP bridge (4-8 weeks)

- `predicate-authorityd`.
- Entra/OIDC bridge.
- token refresh + local revoke.
- deterministic-invariant-triggered token kill.

## Phase 3: Gateway and enterprise controls (8-12 weeks)

- policy-managed gateway mode.
- centralized revocation and distribution.
- audit export integrations and admin tooling.


## Success Metrics

Track outcomes that matter to production reliability and security:

- % sensitive actions with pre-exec authorization gate.
- denial precision (true blocks vs false blocks).
- mean time to root cause (using trace + proof links).
- replay/reproducibility success rate.
- reduction in unauthorized or policy-violating actions.
- token misuse/replay incidents prevented.


## Risks and Mitigations

- **Risk: integration friction with existing agents**
  - Mitigation: wrapper/decorator APIs, sidecar mode, backward-compatible defaults.

- **Risk: latency from extra checks**
  - Mitigation: short local verification paths, cached public keys, bounded policy evaluation.

- **Risk: policy complexity**
  - Mitigation: small policy core, templates by agent type, dry-run mode.

- **Risk: brittle state hash semantics**
  - Mitigation: canonical snapshot schema, stable field selection, versioned hashing.


## Recommended Initial Scope

Start with a narrow but high-impact path:

1. Browser agent critical actions (`click`, `type`, `submit`, `navigate`).
2. MCP tool execution guard.
3. HTTP outbound call guard.

Use existing `sdk-python` assertions as required preconditions and bind authority to those outcomes.

For non-web agents, replace snapshot/predicate preconditions with:

- structured execution context (task id, run id, tool name, input hash),
- policy-bound intent checks (`intent_hash`),
- risk/budget/delegation constraints,
- signed proof events for every allow/deny decision.


## Final Positioning

Predicate should position this as:

**"Deterministic execution + pre-execution authority, with your existing identity stack."**

Not "another IdP," and not "just observability."

This creates a defensible platform where agents are:

- deterministic in behavior verification,
- constrained by cryptographic authority at execution time,
- and provable in audit trails for enterprise governance.

## Milestones and Phased Deliverables

This implementation plan assumes a small cross-functional team (SDK + platform + security + product) and can run as a 4-phase build with explicit exit criteria.

## Phase 0: Architecture and Spec Lock (1-2 weeks)

Objective: freeze contracts so implementation can proceed in parallel.

Deliverables:

- `predicate-contracts` package scaffold and ownership model (tiny shared package).
- `predicate-authority` API spec (Python): `AuthorityClient`, `ActionGuard`, `IdentityBridge`, `ProofLedger`.
- Mandate token schema (claims, signatures, TTL, `intent_hash`, `state_hash`).
- Decision event schema (allow/deny reason codes, trace/artifact references, credit fields).
- Policy DSL v1 spec (principal/action/resource/state/budget/delegation).
- Credit accounting spec for "Verification Credits" (1-credit authority check, 10-credit visual verification).
- package dependency graph + import boundaries documented (`predicate-contracts` -> `predicate-authority` and `sdk-python`).

Exit criteria:

- design review sign-off from SDK, platform, and security.
- versioned schema docs published.
- compatibility mapping to existing `sdk-python` step lifecycle approved.
- release orchestration design approved for multi-package PyPI publishing (`predicate-contracts` then `predicate-authority`).

Current status: **partially complete**

- [x] dependency graph/import boundaries documented in this proposal.
- [x] package scaffolding started in this `predicate-authority` repository (`predicate-contracts`, `predicate-authority`).
- [ ] formal design sign-off from SDK/platform/security.
- [ ] versioned schema docs publication process.
- [ ] approved compatibility mapping with `sdk-python` lifecycle owners.

## Phase 1: Local SDK Guard (MVP) (3-5 weeks)

Objective: deliver immediate value with in-process pre-execution authority.

Deliverables:

- publish `predicate-contracts` v0.x with stable protocol/data contracts.
- `predicate-authority` package with:
  - local `ActionGuard.authorize(...)`,
  - signed local mandates,
  - local policy evaluation,
  - fail-closed behavior and normalized deny reasons.
- `sdk-python` integration hooks (pre-action authority gate + postcondition linkage).
- OpenTelemetry/trace emission for authority events.
- Developer examples for browser, MCP tool, and outbound HTTP action guards.

Exit criteria:

- >90% of targeted sensitive actions can be wrapped with pre-exec checks.
- deterministic regression tests pass for authorize/deny paths.
- developer quickstart validated end-to-end on local-only mode.
- CI release pipeline can publish and verify `predicate-contracts` and `predicate-authority` in dependency order.

Current status: **in progress**

- [x] local `ActionGuard.authorize(...)`.
- [x] signed local mandates.
- [x] local policy evaluation.
- [x] fail-closed deny path with normalized reason enums.
- [x] deterministic regression tests for authorize/deny paths.
- [ ] `sdk-python` runtime integration hooks.
- [ ] OpenTelemetry-native authority event export.
- [ ] quickstart/examples for browser/MCP/outbound HTTP.
- [ ] dependency-ordered package publish pipeline in CI.

## Phase 2: Sidecar + Identity Bridge (4-6 weeks)

Objective: production-ready token lifecycle and enterprise identity compatibility.

Deliverables:

- `predicate-authorityd` sidecar:
  - local secure credential store,
  - short-lived mandate minting/refresh,
  - local revocation cache,
  - policy hot-reload.
- `IdentityBridge` adapters:
  - OIDC generic bridge,
  - Entra bridge first,
  - Okta bridge second.
- optional `predicate-authority-sdk-python-adapter` package for isolated cross-package glue.
- invariant-triggered revocation path (predicate failure can invalidate local capability).
- connected mode toggles (local-only vs cloud-connected).

Exit criteria:

- long-running agent workloads can run without manual token intervention.
- bridge token exchange validated against at least one enterprise IdP.
- sidecar survives restart/network partition with fail-closed guarantees.

Current status: **not started (design only)**

## Phase 3: Hosted Governance Control Plane (6-8 weeks)

Objective: ship monetizable cloud governance capabilities.

Deliverables:

- Audit Vault ingestion API for signed proof events.
- retention tiers (30-day, 1-year, 7-year/WORM-ready path).
- Command Center policy dashboard + fleet sync.
- global kill-switch and revocation fanout (`principal_id`, `intent_hash`, policy tags).
- Verification Credits metering and usage dashboards.

Exit criteria:

- policy updates propagate to active sidecars within target SLA.
- kill-switch propagation meets incident response target.
- billable usage pipeline reconciles authority + snapshot credits accurately.

Current status: **not started (design only)**

## Phase 4: Enterprise Hardening and Scale (ongoing, first 4-6 weeks)

Objective: make it enterprise-ready for regulated production.

Deliverables:

- SSO/admin controls and tenant isolation.
- signed export pipelines for SIEM/SOC workflows.
- compliance evidence packs (audit queries, retention attestations, revocation reports).
- HA/SLO hardening, runbooks, and support escalation paths.
- pricing guardrails (overage behavior, pooled credits, forecasting alerts).

Exit criteria:

- reference customer security review completed.
- defined SLOs met in staging/load tests.
- enterprise onboarding playbook validated with pilot accounts.

Current status: **not started (design only)**

## Cross-Phase Dependencies

- `sdk-python` runtime contract stability (snapshot schema, assertion labels, step metadata).
- `predicate-contracts` semver discipline (breaking changes require coordinated version gates).
- cryptographic key management strategy (local keys vs managed KMS).
- billing/telemetry instrumentation available by Phase 3.
- legal review for open-core licensing and hosted governance terms.

## Proposed Milestone Gates

- **Gate A (end Phase 1):** local SDK MVP usable in one production-like agent flow; `predicate-contracts` + `predicate-authority` publish flow proven.
- **Gate B (end Phase 2):** sidecar + IdP bridge validated for long-running agents.
- **Gate C (end Phase 3):** first monetizable connected tier (Pro) launch-ready.
- **Gate D (end Phase 4):** enterprise tier controls and compliance posture launch-ready.
