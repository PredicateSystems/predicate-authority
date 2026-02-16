# predicate-authority

`predicate-authority` provides pre-execution authorization for AI agent actions.

Core pieces:

- `PolicyEngine` for allow/deny + required verification labels,
- `ActionGuard` for pre-action `authorize` / `enforce`,
- `LocalMandateSigner` for signed short-lived mandates,
- `InMemoryProofLedger` and optional `OpenTelemetryTraceEmitter`,
- typed integration adapters (including `sdk-python` mapping helpers).
