# Architecture

## Overview

`trysac-backup-verifier` provides deterministic backup verification against cryptographic manifests, safe restoration testing, and freshness verification.

### Pipeline

```
+--------------------+     +----------------------+
| Directory to Back  | --> | Manifest (SHA-256)   |
+--------------------+     +----------------------+
                                      |
+--------------------+                v
| Archive (tar/zip)  | --> [ verify_archive / restore_check ] --> Report(ok, issues)
+--------------------+                ^
                                      |
                           +----------------------+
                           | Limits (Decomp Bomb) |
                           +----------------------+
```

### Key Principles

1. **Standard Library Only**: Built entirely using Python's `tarfile`, `zipfile`, `hashlib`, and `json` modules.
2. **Zero Insecure Extraction**: Never invokes `extractall()` or tarfile filters. Files are streamed in 1 MiB chunks with strict running size checks.
3. **OS-Agnostic Path Sanitization**: Blocks relative directory navigation (`..`), absolute paths, Windows drive letters, backslashes, trailing dots/spaces, and DOS device names across all platforms.
4. **Structured Error Codes and Reports**: Identifies discrepancies as typed `Issue` records (`missing`, `extra`, `hash_mismatch`, `size_mismatch`, `unsafe_path`, `unsupported_member`, `duplicate_member`, `stale`, `too_few`, `restore_mismatch`).
