# Okta Example Notes

This note covers running the Okta delegation compatibility demo and fixing the
most common setup issues.

## Prerequisites

- Populate `AgentIdentity/.env` with:
  - `OKTA_ISSUER`
  - `OKTA_CLIENT_ID`
  - `OKTA_CLIENT_SECRET`
  - `OKTA_AUDIENCE`
  - `OKTA_SCOPE` (defaults to `authority:check`)
- Load env vars in your terminal:

```bash
set -a
source .env
set +a
```

## Run the compatibility demo

```bash
python examples/delegation/okta_obo_compat_demo.py \
  --issuer "$OKTA_ISSUER" \
  --client-id "$OKTA_CLIENT_ID" \
  --client-secret "$OKTA_CLIENT_SECRET" \
  --audience "$OKTA_AUDIENCE" \
  --scope "${OKTA_SCOPE:-authority:check}"
```

If your tenant supports token exchange/OBO, add:

```bash
--supports-token-exchange
```

Full command:

```bash
python examples/delegation/okta_obo_compat_demo.py \
  --issuer "$OKTA_ISSUER" \
  --client-id "$OKTA_CLIENT_ID" \
  --client-secret "$OKTA_CLIENT_SECRET" \
  --audience "$OKTA_AUDIENCE" \
  --scope "$OKTA_SCOPE" \
  --supports-token-exchange
```

## Common error: `invalid_scope`

Error example:

```text
HTTP 400 ... {"error":"invalid_scope","error_description":"One or more scopes are not configured for the authorization server resource."}
```

This means the requested scope (for example `authority:check`) is not configured
for your Okta authorization server.

### Fix

1. In Okta Admin, open `Security -> API -> Authorization Servers -> default`.
2. Add scope `authority:check` (or another scope you intend to use).
3. In Access Policies, allow:
   - grant type: `Client Credentials`
   - scope: `authority:check` (or your chosen scope)
4. Re-run the demo.

If you want a quick workaround, set `OKTA_SCOPE` to an existing scope that your
app policy already allows.

## Compatibility behavior

- If `--supports-token-exchange` is set and tenant supports it:
  - output should report `delegation_path: idp_token_exchange`.
- Otherwise:
  - output should report `delegation_path: authority_mandate_delegation`.

This keeps delegation deterministic even when IdP-native OBO is unavailable.
