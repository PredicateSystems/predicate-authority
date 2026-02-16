# PyPI Release Guide

This repo publishes two Python packages in strict order:

1. `predicate-contracts`
2. `predicate-authority` (depends on `predicate-contracts`)

## 1) One-time setup

### Reserve package names on PyPI

Ensure both package names exist under your organization:

- `predicate-contracts`
- `predicate-authority`

### Add GitHub repository secrets

In GitHub repository settings -> Secrets and variables -> Actions, add:

- `PYPI_TOKEN_PREDICATE_CONTRACTS`
- `PYPI_TOKEN_PREDICATE_AUTHORITY`

Use PyPI API tokens scoped to each package where possible.

## 2) Prepare a release

1. Update versions:
   - `predicate_contracts/pyproject.toml` -> `project.version`
   - `predicate_authority/pyproject.toml` -> `project.version`
2. If `predicate-contracts` version changes, update dependency pin in:
   - `predicate_authority/pyproject.toml` (`predicate-contracts>=X,<Y`)
3. Run local checks:

```bash
make test
make lint
make verify-release-order
python -m build predicate_contracts
python -m build predicate_authority
```

## 3) Publish via GitHub Actions (recommended)

1. Push your release commit to `main`.
2. Open Actions -> `phase1-ci-and-release`.
3. Click **Run workflow** with input `publish=true`.
4. Workflow order is enforced:
   - `publish-predicate-contracts`
   - `publish-predicate-authority` (runs only after contracts publish succeeds)

## 4) Verify published artifacts

```bash
python -m pip install --upgrade predicate-contracts predicate-authority
python - <<'PY'
import predicate_contracts
import predicate_authority
print("ok", predicate_contracts.__name__, predicate_authority.__name__)
PY
```

## 5) Manual fallback publish (if needed)

```bash
python -m pip install --upgrade build twine
python -m build predicate_contracts
twine check predicate_contracts/dist/*
TWINE_USERNAME=__token__ TWINE_PASSWORD="$PYPI_TOKEN_PREDICATE_CONTRACTS" twine upload predicate_contracts/dist/*

python -m build predicate_authority
twine check predicate_authority/dist/*
TWINE_USERNAME=__token__ TWINE_PASSWORD="$PYPI_TOKEN_PREDICATE_AUTHORITY" twine upload predicate_authority/dist/*
```
