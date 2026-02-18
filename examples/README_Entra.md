# Entra Example Notes

This note covers running the Entra OBO compatibility demo and common setup outcomes.

## Prerequisites

- Populate `AgentIdentity/.env` with:
  - `ENTRA_TENANT_ID`
  - `ENTRA_CLIENT_ID`
  - `ENTRA_CLIENT_SECRET`
  - `ENTRA_SCOPE` (for example `api://predicate-authority/.default`)
  - optional for OBO path: `ENTRA_USER_ASSERTION`
- Load env vars:

```bash
set -a
source .env
set +a
```

## Run Entra compatibility demo

```bash
python examples/delegation/entra_obo_compat_demo.py \
  --tenant-id "$ENTRA_TENANT_ID" \
  --client-id "$ENTRA_CLIENT_ID" \
  --client-secret "$ENTRA_CLIENT_SECRET" \
  --scope "$ENTRA_SCOPE"
```

If tenant supports OBO and you have a user assertion token:

```bash
python examples/delegation/entra_obo_compat_demo.py \
  --tenant-id "$ENTRA_TENANT_ID" \
  --client-id "$ENTRA_CLIENT_ID" \
  --client-secret "$ENTRA_CLIENT_SECRET" \
  --scope "$ENTRA_SCOPE" \
  --user-assertion "$ENTRA_USER_ASSERTION" \
  --supports-obo
```

## Common outcomes

- `obo_reason=tenant_capability_disabled`:
  - tenant/app is not configured for OBO, fallback delegation path should be used.
- `obo_reason=user_assertion_required`:
  - OBO is requested but no user assertion was provided.
- `unauthorized_client` from token endpoint:
  - app registration is not authorized for the requested OBO grant/policy.

## Compatibility behavior

- OBO success -> `delegation_path: idp_obo_token_exchange`.
- OBO unavailable/not configured -> `delegation_path: authority_mandate_delegation`.
