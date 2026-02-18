# OIDC Example Notes

This note covers running the generic OIDC token-exchange compatibility demo.

## Prerequisites

- Populate `AgentIdentity/.env` with:
  - `OIDC_ISSUER`
  - `OIDC_CLIENT_ID`
  - `OIDC_CLIENT_SECRET`
  - `OIDC_AUDIENCE`
  - `OIDC_SCOPE` (default `authority:check`)
- Load env vars:

```bash
set -a
source .env
set +a
```

## Run OIDC compatibility demo

```bash
python examples/delegation/oidc_compat_demo.py \
  --issuer "$OIDC_ISSUER" \
  --client-id "$OIDC_CLIENT_ID" \
  --client-secret "$OIDC_CLIENT_SECRET" \
  --audience "$OIDC_AUDIENCE" \
  --scope "${OIDC_SCOPE:-authority:check}"
```

If provider supports token exchange and you have a subject token:

```bash
python examples/delegation/oidc_compat_demo.py \
  --issuer "$OIDC_ISSUER" \
  --client-id "$OIDC_CLIENT_ID" \
  --client-secret "$OIDC_CLIENT_SECRET" \
  --audience "$OIDC_AUDIENCE" \
  --scope "${OIDC_SCOPE:-authority:check}" \
  --subject-token "$OIDC_SUBJECT_TOKEN" \
  --supports-token-exchange
```

## Compatibility behavior

- token exchange success -> `delegation_path: idp_token_exchange`
- token exchange unavailable or unsupported -> `delegation_path: authority_mandate_delegation`
