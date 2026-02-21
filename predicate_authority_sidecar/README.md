# predicate-authority-sidecar

Predicate Authority Sidecar binary installer for Python.

This package provides tools to download and run the Predicate Authority sidecar binary.

## Installation

```bash
pip install predicate-authority-sidecar
```

Or as an optional dependency of predicate-authority:

```bash
pip install "predicate-authority[sidecar]"
```

> **Note:** Use quotes around `predicate-authority[sidecar]` to prevent shell glob expansion in zsh.

## Important: Manual Download Required

**The binary is NOT downloaded automatically during pip install.** You must manually trigger the download:

```bash
predicate-download-sidecar
```

Or with a specific version:

```bash
predicate-download-sidecar --version v0.3.8
```

The binary is placed in your platform's data directory:
- macOS: `~/Library/Application Support/predicate-authority/bin/predicate-authorityd`
- Linux: `~/.local/share/predicate-authority/bin/predicate-authorityd`
- Windows: `%LOCALAPPDATA%/predicate-authority/bin/predicate-authorityd.exe`

## Usage

### From Python

```python
from predicate_authority import run_sidecar, get_sidecar_path, is_sidecar_available, download_sidecar

# Download if not available
if not is_sidecar_available():
    download_sidecar()

# Check path
print(get_sidecar_path())

# Run sidecar
process = run_sidecar(port=8787, policy_file="policy.json")

# Later: graceful shutdown
process.terminate()
process.wait()
```

### From Command Line

**IMPORTANT:** CLI arguments must be placed **before** the `run` subcommand.

```bash
# Get the binary path
SIDECAR=$(python -c "from predicate_authority import get_sidecar_path; print(get_sidecar_path())")

# Show help
"$SIDECAR" --help

# Start in local mode
"$SIDECAR" \
  --host 127.0.0.1 \
  --port 8787 \
  --mode local_only \
  --policy-file policy.json \
  run

# Using environment variables
export PREDICATE_HOST=127.0.0.1
export PREDICATE_PORT=8787
export PREDICATE_MODE=local_only
export PREDICATE_POLICY_FILE=policy.json
"$SIDECAR" run

# Generate example config
"$SIDECAR" init-config --output config.toml

# Run with config file
"$SIDECAR" --config config.toml run
```

### CLI Reference

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

COMMANDS:
  run          Start the daemon (default)
  init-config  Generate example config file
  check-config Validate config file
  version      Show version info
```

## Supported Platforms

| Platform | Architecture |
|----------|--------------|
| macOS | Apple Silicon (arm64) |
| macOS | Intel (x64) |
| Linux | x64 |
| Linux | arm64 |
| Windows | x64 |

## License

MIT / Apache-2.0
