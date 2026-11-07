# backup-verifier

[![PyPI version](https://img.shields.io/pypi/v/trysac-backup-verifier)](https://pypi.org/project/trysac-backup-verifier/)
[![License: MIT](https://img.shields.io/pypi/l/trysac-backup-verifier)](LICENSE)
[![CI](https://github.com/Trysac/u185-backup-verifier/actions/workflows/ci.yml/badge.svg)](https://github.com/Trysac/u185-backup-verifier/actions/workflows/ci.yml)

Verify backup archives against a SHA-256 manifest, test restores safely into an empty directory and check freshness with an injected clock

## Problem

Describe in two or three sentences the concrete problem this utility solves, who hits it, and what
they do today without it. Replace this paragraph when the first real feature lands.

## Install

```sh
pip install trysac-backup-verifier
# or
uv add trysac-backup-verifier
```

Requires Python 3.10 or newer. No runtime dependencies.

## Usage

```python
import backup_verifier

# normalize() trims surrounding whitespace and lower-cases the text.
print(backup_verifier.normalize("  Hello World "))  # -> "hello world"

# Blank input is rejected explicitly instead of returning an empty string.
try:
    backup_verifier.normalize("   ")
except ValueError as exc:
    print(f"rejected: {exc}")
```

## Documentation

- [Architecture](docs/ARCHITECTURE.md) and [decisions](docs/decisions/)
- [Testing](docs/TESTING.md) and [security](docs/SECURITY.md)
- [Project record](docs/PROJECT.md) and [stack](docs/STACK.md)
- [Changelog](CHANGELOG.md) and [contributing guide](CONTRIBUTING.md)

## License

[MIT](LICENSE) (c) 2026 Miguel Gomez
