# Security Model and Threat Analysis

## Defended Threats

- **Path Traversal**: `is_unsafe_path` rejects empty names, NUL characters, absolute paths (`/x`, `C:x`, `\\host`), `..` components, backslashes, and Windows reserved device names (CON, PRN, AUX, NUL, COM1-9, LPT1-9). This is consistent across all operating systems.
- **Decompression Bombs**: Verification streams archives in 1 MiB chunks, enforcing strict byte counts against `Limits` (default: 100,000 members, 10 GiB total, 4 GiB per member).
- **Device Nodes and Links**: Symlinks, hardlinks, and device nodes are classified as `unsupported_member` and are never extracted.
- **Restore Safety**: `restore_check` enforces existence of an empty destination, creates directories using `mkdir`, and writes files using `xb` mode to prevent overwriting or following existing file handles.

## Not Defended

- **Encrypted Archives**: Does not support decryption; encrypted archives are treated as unreadable.
- **Malicious Payload**: Does not perform virus or malware scanning on valid file contents.
- **TOCTOU**: Destination directory integrity is not defended against concurrent modification during `restore_check`.