# Testing

## Coverage

- `tests/test_backup_verifier.py`: Exercises the public API including manifest generation, archive verification, restore checks, and freshness monitoring.
- Tests are deterministic, utilizing `tmp_path` to build archives and verify behavior without external network or system clock dependencies.
- Assertions verify return values, reported issues, and raised `BackupError` codes for specific invalid input scenarios.
- Tests ensure no code path invokes non-safe extractions.