# predicate-authority

`predicate-authority` is a deterministic pre-execution authority layer for AI agents.
It binds identity, policy, and runtime evidence so risky actions are authorized
before execution and denied fail-closed when checks do not pass.

Docs: https://www.PredicateSystems.ai/docs

Core pieces:

- `PolicyEngine` for allow/deny + required verification labels,
- `ActionGuard` for pre-action `authorize` / `enforce`,
- `LocalMandateSigner` for signed short-lived mandates,
- `InMemoryProofLedger` and optional `OpenTelemetryTraceEmitter`,
- typed integration adapters (including `sdk-python` mapping helpers),
- control-plane client primitives for shipping proof and usage batches to hosted APIs,
- local identity registry primitives (ephemeral task identities + local flush queue).
