"""Deterministic backup archive verification and safe restore checks."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import tarfile
import zipfile
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path, PurePosixPath
from typing import Any, Literal

__all__ = [
    "BackupError",
    "BackupErrorCode",
    "BackupEvent",
    "BackupInfo",
    "Entry",
    "Issue",
    "IssueCode",
    "Limits",
    "Manifest",
    "Report",
    "check_freshness",
    "create_manifest",
    "restore_check",
    "verify_archive",
]

__version__ = "0.1.0"

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

CHUNK_SIZE = 1024 * 1024  # 1 MiB
MAX_MANIFEST_TEXT_BYTES = 50 * 1024 * 1024  # 50 MiB
MANIFEST_FORMAT = "backup-manifest/1"

BackupErrorCode = Literal[
    "unreadable_archive",
    "limit_exceeded",
    "invalid_manifest",
    "invalid_option",
    "dest_not_empty",
]

IssueCode = Literal[
    "missing",
    "extra",
    "hash_mismatch",
    "size_mismatch",
    "unsafe_path",
    "unsupported_member",
    "duplicate_member",
    "stale",
    "too_few",
    "restore_mismatch",
]

WINDOWS_RESERVED_NAMES = frozenset(
    {
        "CON",
        "PRN",
        "AUX",
        "NUL",
        "COM1",
        "COM2",
        "COM3",
        "COM4",
        "COM5",
        "COM6",
        "COM7",
        "COM8",
        "COM9",
        "LPT1",
        "LPT2",
        "LPT3",
        "LPT4",
        "LPT5",
        "LPT6",
        "LPT7",
        "LPT8",
        "LPT9",
    }
)


class BackupError(Exception):
    """Base exception for all backup-verifier errors with a stable machine code."""

    def __init__(self, code: BackupErrorCode, message: str) -> None:
        super().__init__(message[:200])
        self.code: BackupErrorCode = code
        self.message = message[:200]

    def __str__(self) -> str:
        return f"[{self.code}] {self.message}"


@dataclass(frozen=True, slots=True)
class Issue:
    """Represents a discrepancy, defect, or safety violation detected in an archive."""

    code: IssueCode
    path: str

    def __lt__(self, other: Any) -> bool:
        if not isinstance(other, Issue):
            return NotImplemented
        return (self.path, self.code) < (other.path, other.code)


@dataclass(frozen=True, slots=True)
class Report:
    """Outcome of an archive verification or restore check."""

    ok: bool
    issues: tuple[Issue, ...]


@dataclass(frozen=True, slots=True)
class BackupEvent:
    """Telemetry event emitted during verification or restore checks."""

    kind: str
    path: str
    code: IssueCode | None


EventCallback = Callable[[BackupEvent], None]


@dataclass(frozen=True, slots=True)
class Entry:
    """A manifest entry representing a single file with expected size and SHA-256 hash."""

    path: str
    size: int
    sha256: str


@dataclass(frozen=True, slots=True)
class Limits:
    """Resource bounds to guard against decompression bombs and denial-of-service."""

    max_members: int = 100_000
    max_total_bytes: int = 10 * 1024**3
    max_member_bytes: int = 4 * 1024**3


DEFAULT_LIMITS = Limits()


@dataclass(frozen=True, slots=True)
class BackupInfo:
    """Metadata for an existing backup artifact used for freshness validation."""

    name: str
    created_at: datetime


@dataclass(frozen=True, slots=True)
class Manifest:
    """Cryptographic manifest of expected files in a backup."""

    entries: tuple[Entry, ...]

    def to_json(self) -> str:
        """Serialize the manifest into deterministic JSON sorted by key and entry path."""
        sorted_entries = sorted(self.entries, key=lambda e: e.path)
        data = {
            "format": MANIFEST_FORMAT,
            "entries": [
                {"path": e.path, "sha256": e.sha256, "size": e.size} for e in sorted_entries
            ],
        }
        return json.dumps(data, indent=2, sort_keys=True)

    @classmethod
    def from_json(cls, text: str) -> Manifest:
        """Parse and validate manifest JSON."""
        if len(text.encode("utf-8")) > MAX_MANIFEST_TEXT_BYTES:
            raise BackupError("invalid_manifest", "Manifest text exceeds maximum size limit")
        try:
            data = json.loads(text)
        except Exception as exc:
            raise BackupError("invalid_manifest", f"Malformed manifest JSON: {exc}") from exc

        if not isinstance(data, dict):
            raise BackupError("invalid_manifest", "Manifest JSON must be an object")

        if data.get("format") != MANIFEST_FORMAT:
            raise BackupError(
                "invalid_manifest", f"Unsupported manifest format: {data.get('format')}"
            )

        raw_entries = data.get("entries")
        if not isinstance(raw_entries, list):
            raise BackupError("invalid_manifest", "Manifest 'entries' must be a list")

        entries: list[Entry] = []
        seen_paths: set[str] = set()
        for item in raw_entries:
            if not isinstance(item, dict):
                raise BackupError("invalid_manifest", "Entry in manifest must be an object")
            path = item.get("path")
            size = item.get("size")
            sha = item.get("sha256")

            if not isinstance(path, str) or not isinstance(size, int) or not isinstance(sha, str):
                raise BackupError("invalid_manifest", "Invalid types in manifest entry")
            if is_unsafe_path(path):
                raise BackupError("invalid_manifest", f"Unsafe path in manifest: {path}")
            if size < 0:
                raise BackupError("invalid_manifest", f"Negative size in entry {path}")
            if len(sha) != 64 or not all(c in "0123456789abcdef" for c in sha):
                raise BackupError(
                    "invalid_manifest",
                    f"SHA-256 must be a 64-character lowercase hex string: {sha}",
                )
            if path in seen_paths:
                raise BackupError("invalid_manifest", f"Duplicate path in manifest: {path}")
            seen_paths.add(path)
            entries.append(Entry(path=path, size=size, sha256=sha))

        entries.sort(key=lambda e: e.path)
        return cls(entries=tuple(entries))


def is_unsafe_path(path_str: str) -> bool:
    """Determine whether a relative POSIX path violates security boundary rules on any OS."""
    if not path_str or "\x00" in path_str:
        return True
    if "\\" in path_str:
        return True
    if path_str.startswith("/"):
        return True
    # Windows drive letters or absolute colons
    if len(path_str) >= 2 and path_str[1] == ":":
        return True
    # Windows UNC path
    if path_str.startswith("//"):
        return True

    parts = PurePosixPath(path_str).parts
    if not parts:
        return True

    for part in parts:
        if part in (".", ".."):
            return True
        if part.endswith(" ") or part.endswith("."):
            return True
        if ":" in part:
            return True
        stem = part.split(".")[0].upper()
        if stem in WINDOWS_RESERVED_NAMES:
            return True
    return False


def _hash_file(file_path: Path) -> tuple[int, str]:
    hasher = hashlib.sha256()
    size = 0
    with open(file_path, "rb") as f:
        while chunk := f.read(CHUNK_SIZE):
            hasher.update(chunk)
            size += len(chunk)
    return size, hasher.hexdigest()


def create_manifest(root: Path, *, max_files: int = 100_000) -> Manifest:
    """Traverse root directory and build a sorted SHA-256 Manifest of all regular files."""
    if not root.is_dir():
        raise BackupError("invalid_option", f"Root path is not a directory: {root}")

    entries: list[Entry] = []
    count = 0
    for dirpath, _, filenames in os.walk(root):
        for fname in filenames:
            count += 1
            if count > max_files:
                raise BackupError("limit_exceeded", f"Exceeded maximum file count {max_files}")
            full_path = Path(dirpath) / fname
            if full_path.is_symlink():
                continue
            rel_path = full_path.relative_to(root).as_posix()
            if is_unsafe_path(rel_path):
                raise BackupError("invalid_option", f"Unsafe relative path encountered: {rel_path}")
            size, sha = _hash_file(full_path)
            entries.append(Entry(path=rel_path, size=size, sha256=sha))

    entries.sort(key=lambda e: e.path)
    return Manifest(entries=tuple(entries))


class _ArchiveMember:
    def __init__(
        self,
        name: str,
        is_dir: bool,
        is_regular: bool,
        is_link_or_special: bool,
        open_stream: Any,
        reported_size: int | None = None,
    ) -> None:
        self.name = name
        self.is_dir = is_dir
        self.is_regular = is_regular
        self.is_link_or_special = is_link_or_special
        self.open_stream = open_stream
        self.reported_size = reported_size


@contextmanager
def _open_archive(archive_path: Path) -> Iterator[tuple[str, Any]]:
    if not archive_path.is_file():
        raise BackupError("unreadable_archive", f"Archive not found or not a file: {archive_path}")

    # Try tarfile (supports uncompressed, gz, bz2, xz)
    try:
        if tarfile.is_tarfile(archive_path):
            with tarfile.open(archive_path, mode="r:*") as tf:
                yield "tar", tf
            return
    except (tarfile.TarError, EOFError, OSError):
        pass

    # Try zipfile
    try:
        if zipfile.is_zipfile(archive_path):
            with zipfile.ZipFile(archive_path, mode="r") as zf:
                yield "zip", zf
            return
    except (zipfile.BadZipFile, OSError):
        pass

    raise BackupError("unreadable_archive", f"Unrecognized or unreadable archive: {archive_path}")


def _iter_archive_members(kind: str, archive_obj: Any) -> list[_ArchiveMember]:
    members: list[_ArchiveMember] = []
    if kind == "tar":
        tf: tarfile.TarFile = archive_obj
        for ti in tf.getmembers():
            is_dir = ti.isdir()
            is_reg = ti.isreg()
            is_special = (
                ti.issym()
                or ti.islnk()
                or ti.ischr()
                or ti.isblk()
                or ti.isfifo()
                or (not is_dir and not is_reg)
            )
            member_name = ti.name

            def make_opener(ti_target: tarfile.TarInfo) -> Callable[[], Any]:
                def opener() -> Any:
                    return tf.extractfile(ti_target)

                return opener

            members.append(
                _ArchiveMember(
                    name=member_name,
                    is_dir=is_dir,
                    is_regular=is_reg,
                    is_link_or_special=is_special,
                    open_stream=make_opener(ti),
                    reported_size=ti.size,
                )
            )
    elif kind == "zip":
        zf: zipfile.ZipFile = archive_obj
        for zi in zf.infolist():
            is_dir = zi.is_dir()
            # In zip, symlinks have high bits in external_attr == 0xA000
            mode = zi.external_attr >> 16
            is_symlink = (mode & 0o170000) == 0o120000
            is_reg = (not is_dir) and (not is_symlink)
            is_special = is_symlink
            member_name = zi.filename

            def make_zip_opener(zi_target: zipfile.ZipInfo) -> Callable[[], Any]:
                def opener() -> Any:
                    return zf.open(zi_target, mode="r")

                return opener

            members.append(
                _ArchiveMember(
                    name=member_name,
                    is_dir=is_dir,
                    is_regular=is_reg,
                    is_link_or_special=is_special,
                    open_stream=make_zip_opener(zi),
                    reported_size=zi.file_size,
                )
            )
    return members


def verify_archive(
    archive: Path,
    manifest: Manifest,
    *,
    limits: Limits = DEFAULT_LIMITS,
    on_event: EventCallback | None = None,
) -> Report:
    """Verify an archive against a manifest without extracting files to disk."""
    with _open_archive(archive) as (kind, archive_obj):
        issues: list[Issue] = []

        def emit(event: BackupEvent) -> None:
            if on_event:
                on_event(event)

        manifest_map = {e.path: e for e in manifest.entries}
        seen_archive_paths: set[str] = set()
        total_bytes_read = 0
        total_members_seen = 0

        members = _iter_archive_members(kind, archive_obj)
        for member in members:
            if member.is_dir:
                continue

            total_members_seen += 1
            if total_members_seen > limits.max_members:
                raise BackupError(
                    "limit_exceeded",
                    f"Total archive members exceeded limit of {limits.max_members}",
                )

            name = member.name
            # Check duplicate
            if name in seen_archive_paths:
                iss = Issue("duplicate_member", name)
                issues.append(iss)
                emit(BackupEvent("issue", name, "duplicate_member"))
                continue
            seen_archive_paths.add(name)

            # Check safety
            if is_unsafe_path(name):
                iss = Issue("unsafe_path", name)
                issues.append(iss)
                emit(BackupEvent("issue", name, "unsafe_path"))
                continue

            # Check unsupported (symlink, hardlink, dev)
            if member.is_link_or_special or not member.is_regular:
                iss = Issue("unsupported_member", name)
                issues.append(iss)
                emit(BackupEvent("issue", name, "unsupported_member"))
                continue

            # Check extra
            if name not in manifest_map:
                iss = Issue("extra", name)
                issues.append(iss)
                emit(BackupEvent("issue", name, "extra"))
                # Still stream to enforce byte limits
                stream = member.open_stream()
                if stream is not None:
                    with stream:
                        member_bytes = 0
                        while chunk := stream.read(CHUNK_SIZE):
                            member_bytes += len(chunk)
                            total_bytes_read += len(chunk)
                            if member_bytes > limits.max_member_bytes:
                                raise BackupError(
                                    "limit_exceeded",
                                    f"Member {name} exceeded size limit {limits.max_member_bytes}",
                                )
                            if total_bytes_read > limits.max_total_bytes:
                                raise BackupError(
                                    "limit_exceeded",
                                    f"Total bytes exceeded limit {limits.max_total_bytes}",
                                )
                continue

            expected = manifest_map[name]
            stream = member.open_stream()
            if stream is None:
                iss = Issue("hash_mismatch", name)
                issues.append(iss)
                emit(BackupEvent("issue", name, "hash_mismatch"))
                continue

            hasher = hashlib.sha256()
            member_bytes = 0
            with stream:
                while chunk := stream.read(CHUNK_SIZE):
                    member_bytes += len(chunk)
                    total_bytes_read += len(chunk)
                    if member_bytes > limits.max_member_bytes:
                        raise BackupError(
                            "limit_exceeded",
                            f"Member {name} exceeded size limit {limits.max_member_bytes}",
                        )
                    if total_bytes_read > limits.max_total_bytes:
                        raise BackupError(
                            "limit_exceeded",
                            f"Total bytes exceeded limit {limits.max_total_bytes}",
                        )
                    hasher.update(chunk)

            emit(BackupEvent("member_checked", name, None))

            if member_bytes != expected.size:
                iss = Issue("size_mismatch", name)
                issues.append(iss)
                emit(BackupEvent("issue", name, "size_mismatch"))
            elif hasher.hexdigest() != expected.sha256:
                iss = Issue("hash_mismatch", name)
                issues.append(iss)
                emit(BackupEvent("issue", name, "hash_mismatch"))

        # Check missing
        for expected_path in sorted(manifest_map.keys()):
            if expected_path not in seen_archive_paths:
                iss = Issue("missing", expected_path)
                issues.append(iss)
                emit(BackupEvent("issue", expected_path, "missing"))

    issues.sort(key=lambda i: (i.path, i.code))
    return Report(ok=(len(issues) == 0), issues=tuple(issues))


def restore_check(
    archive: Path,
    manifest: Manifest,
    dest: Path,
    *,
    limits: Limits = DEFAULT_LIMITS,
    on_event: EventCallback | None = None,
) -> Report:
    """Safely extract only regular, safe manifest entries to empty dest, then verify hashes."""
    if not dest.exists():
        raise BackupError("dest_not_empty", f"Destination directory does not exist: {dest}")
    if not dest.is_dir():
        raise BackupError("dest_not_empty", f"Destination is not a directory: {dest}")
    if any(dest.iterdir()):
        raise BackupError("dest_not_empty", f"Destination directory is not empty: {dest}")

    with _open_archive(archive) as (kind, archive_obj):
        issues: list[Issue] = []

        def emit(event: BackupEvent) -> None:
            if on_event:
                on_event(event)

        manifest_map = {e.path: e for e in manifest.entries}
        seen_archive_paths: set[str] = set()
        total_bytes_read = 0
        total_members_seen = 0

        written_files: list[str] = []

        members = _iter_archive_members(kind, archive_obj)
        for member in members:
            if member.is_dir:
                continue

            total_members_seen += 1
            if total_members_seen > limits.max_members:
                raise BackupError(
                    "limit_exceeded",
                    f"Total archive members exceeded limit of {limits.max_members}",
                )

            name = member.name
            if name in seen_archive_paths:
                iss = Issue("duplicate_member", name)
                issues.append(iss)
                emit(BackupEvent("issue", name, "duplicate_member"))
                continue
            seen_archive_paths.add(name)

            if is_unsafe_path(name):
                iss = Issue("unsafe_path", name)
                issues.append(iss)
                emit(BackupEvent("issue", name, "unsafe_path"))
                continue

            if member.is_link_or_special or not member.is_regular:
                iss = Issue("unsupported_member", name)
                issues.append(iss)
                emit(BackupEvent("issue", name, "unsupported_member"))
                continue

            if name not in manifest_map:
                iss = Issue("extra", name)
                issues.append(iss)
                emit(BackupEvent("issue", name, "extra"))
                continue

            expected = manifest_map[name]
            target_path = dest / PurePosixPath(name)
            target_path.parent.mkdir(parents=True, exist_ok=True)

            stream = member.open_stream()
            if stream is None:
                iss = Issue("hash_mismatch", name)
                issues.append(iss)
                emit(BackupEvent("issue", name, "hash_mismatch"))
                continue

            member_bytes = 0
            with stream, open(target_path, "xb") as out_f:
                while chunk := stream.read(CHUNK_SIZE):
                    member_bytes += len(chunk)
                    total_bytes_read += len(chunk)
                    if member_bytes > limits.max_member_bytes:
                        raise BackupError(
                            "limit_exceeded",
                            f"Member {name} exceeded size limit {limits.max_member_bytes}",
                        )
                    if total_bytes_read > limits.max_total_bytes:
                        raise BackupError(
                            "limit_exceeded",
                            f"Total bytes exceeded limit {limits.max_total_bytes}",
                        )
                    out_f.write(chunk)

            written_files.append(name)
            emit(BackupEvent("member_checked", name, None))

            if member_bytes != expected.size:
                iss = Issue("size_mismatch", name)
                issues.append(iss)
                emit(BackupEvent("issue", name, "size_mismatch"))

        # Missing members
        for expected_path in sorted(manifest_map.keys()):
            if expected_path not in seen_archive_paths:
                iss = Issue("missing", expected_path)
                issues.append(iss)
                emit(BackupEvent("issue", expected_path, "missing"))

        # Re-hash all written files from disk to detect any disk write or restore discrepancy
        for rel_name in written_files:
            expected = manifest_map[rel_name]
            target_path = dest / PurePosixPath(rel_name)
            actual_size, actual_sha = _hash_file(target_path)
            if actual_size != expected.size:
                # If size mismatch wasn't already caught
                if not any(i.path == rel_name and i.code == "size_mismatch" for i in issues):
                    iss = Issue("size_mismatch", rel_name)
                    issues.append(iss)
                    emit(BackupEvent("issue", rel_name, "size_mismatch"))
            elif actual_sha != expected.sha256:
                # Size matched, but written hash differs
                iss = Issue("restore_mismatch", rel_name)
                issues.append(iss)
                emit(BackupEvent("issue", rel_name, "restore_mismatch"))

    issues.sort(key=lambda i: (i.path, i.code))
    return Report(ok=(len(issues) == 0), issues=tuple(issues))


def check_freshness(
    backups: Sequence[BackupInfo],
    *,
    now: datetime,
    max_age: timedelta,
    min_count: int = 1,
) -> list[Issue]:
    """Verify that backups are sufficiently recent and meet the minimum count threshold."""
    if now.tzinfo is None or now.tzinfo.utcoffset(now) is None:
        raise BackupError("invalid_option", "'now' must be a timezone-aware datetime")

    for b in backups:
        if b.created_at.tzinfo is None or b.created_at.tzinfo.utcoffset(b.created_at) is None:
            raise BackupError("invalid_option", f"Backup '{b.name}' has naive created_at datetime")

    issues: list[Issue] = []
    if len(backups) < min_count:
        issues.append(Issue("too_few", "*"))

    if not backups:
        return sorted(issues, key=lambda i: (i.path, i.code))

    newest = max(backups, key=lambda b: b.created_at)
    age = now - newest.created_at
    if age > max_age:
        issues.append(Issue("stale", newest.name))

    issues.sort(key=lambda i: (i.path, i.code))
    return issues
