# predicate-authority-sidecar

Predicate Authority Sidecar binary installer for Python.

This package automatically downloads the Predicate Authority sidecar binary for your platform.

## Installation

```bash
pip install predicate-authority-sidecar
```

Or as an optional dependency of predicate-authority:

```bash
pip install predicate-authority[sidecar]
```

## What happens on install

1. The package is installed with its dependencies
2. On first import, the sidecar binary is downloaded from GitHub releases
3. The binary is placed in your platform's data directory:
   - macOS: `~/Library/Application Support/predicate-authority/bin/`
   - Linux: `~/.local/share/predicate-authority/bin/`
   - Windows: `%LOCALAPPDATA%/predicate-authority/bin/`

## Manual download

You can also trigger a download manually:

```bash
predicate-download-sidecar
```

Or with a specific version:

```bash
predicate-download-sidecar --version v0.1.0
```

## Usage

After installation:

```python
from predicate_authority import run_sidecar, get_sidecar_path

# Check path
print(get_sidecar_path())

# Run sidecar
process = run_sidecar(port=8787, policy_file="policy.json")
```

Or from command line:

```bash
# Get the binary path
python -c "from predicate_authority import get_sidecar_path; print(get_sidecar_path())"

# Run it
$(python -c "from predicate_authority import get_sidecar_path; print(get_sidecar_path())") run --port 8787
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
