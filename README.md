# backup-verifier

[![CI](https://github.com/Trysac/u185-backup-verifier/actions/workflows/ci.yml/badge.svg)](https://github.com/Trysac/u185-backup-verifier/actions/workflows/ci.yml)

Backups are often written nightly but never read until critical failures, potentially revealing truncation or corruption. This utility provides deterministic backup archive verification against cryptographic manifests, safe restoration simulation, and freshness monitoring.

## Installation

```bash
pip install trysac-backup-verifier
```

## Usage Example

```python
from pathlib import Path
from backup_verifier import create_manifest, verify_archive

manifest = create_manifest(Path("./data"))
Path("manifest.json").write_text(manifest.to_json())
report = verify_archive(Path("backup.tar.gz"), manifest)
if not report.ok:
    print(f"Found {len(report.issues)} backup issues:", [i.code for i in report.issues])
```

## Public API Summary

- `create_manifest(root: Path, *, max_files: int = 100_000) -> Manifest`
- `Manifest` (dataclass, `to_json()`/`from_json()`): Deterministic cryptographic manifest.
- `verify_archive(archive: Path, manifest: Manifest, *, limits: Limits = Limits(), on_event=None) -> Report`
- `restore_check(archive: Path, manifest: Manifest, dest: Path, *, limits: Limits = Limits(), on_event=None) -> Report`
- `check_freshness(backups: Sequence[BackupInfo], *, now: datetime, max_age: timedelta, min_count: int = 1) -> list[Issue]`
- `Limits` (dataclass): Bounds for `max_members`, `max_total_bytes`, and `max_member_bytes`.

### Limits and Errors

Verification detects `missing`, `extra`, `hash_mismatch`, `size_mismatch`, `unsafe_path`, `unsupported_member`, `duplicate_member`, `stale`, `too_few`, and `restore_mismatch`. Errors raise `BackupError` with codes `unreadable_archive`, `limit_exceeded`, `invalid_manifest`, `invalid_option`, or `dest_not_empty`.

## Why not Restic?

This utility is designed for simple standard-format archives (tar/zip), providing a lightweight, dependency-free method to verify integrity without requiring a proprietary backup repository format.

See docs/SECURITY.md for safety guarantees.