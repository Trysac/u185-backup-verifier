# Deterministic backup verification and safe restore architecture

Status: accepted (generated, pending human review)

## Context

Backup integrity validation requires verifying archive completeness and cryptographic hashes without risking remote code execution, path traversal, or resource exhaustion from untrusted archive contents.

## Decision

Implement chunked in-memory reading with running resource limits, explicit path safety checks for both POSIX and Windows vulnerabilities, strict manifest schema validation, and safe file-by-file restore into clean target directories.

## Consequences

Guarantees identical, deterministic behavior across Python 3.10-3.13 on POSIX and Windows without third-party dependencies.
