# predicate-contracts

`predicate-contracts` is the shared contract package for Predicate authority workflows.

It contains:

- typed data contracts (`ActionRequest`, `PolicyRule`, `AuthorizationDecision`, etc.),
- integration protocols (`StateEvidenceProvider`, `VerificationEvidenceProvider`, `TraceEmitter`),
- no runtime dependency on `sdk-python` internals or authority runtime logic.
