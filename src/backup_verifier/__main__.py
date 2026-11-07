"""Command line interface for backup_verifier."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from backup_verifier import (
    BackupError,
    Limits,
    Manifest,
    create_manifest,
    restore_check,
    verify_archive,
)


def main(argv: list[str] | None = None) -> int:
    """CLI entry point for backup_verifier."""
    parser = argparse.ArgumentParser(
        prog="backup-verifier",
        description="Verify backup archives against cryptographic manifests safely.",
    )
    subparsers = parser.add_subparsers(dest="subcommand", required=True)

    # manifest ROOT -o FILE
    p_manifest = subparsers.add_parser("manifest", help="Generate a manifest from a directory")
    p_manifest.add_argument("root", type=Path, help="Root directory to manifest")
    p_manifest.add_argument("-o", "--output", type=Path, required=True, help="Output JSON file")

    # verify ARCHIVE MANIFEST
    p_verify = subparsers.add_parser("verify", help="Verify an archive against a manifest")
    p_verify.add_argument("archive", type=Path, help="Backup archive file (tar, tar.gz, zip)")
    p_verify.add_argument("manifest", type=Path, help="Manifest JSON file")

    # restore-check ARCHIVE MANIFEST --dest DIR
    p_restore = subparsers.add_parser(
        "restore-check", help="Simulate safe restoration into an empty destination"
    )
    p_restore.add_argument("archive", type=Path, help="Backup archive file")
    p_restore.add_argument("manifest", type=Path, help="Manifest JSON file")
    p_restore.add_argument("--dest", type=Path, required=True, help="Empty destination directory")

    args = parser.parse_args(argv)

    try:
        if args.subcommand == "manifest":
            manifest = create_manifest(args.root)
            args.output.write_text(manifest.to_json(), encoding="utf-8")
            print(f"Wrote manifest with {len(manifest.entries)} entries to {args.output}")
            return 0

        if args.subcommand == "verify":
            manifest_text = args.manifest.read_text(encoding="utf-8")
            manifest = Manifest.from_json(manifest_text)
            report = verify_archive(args.archive, manifest, limits=Limits())
            if not report.ok:
                for issue in report.issues:
                    print(f"ISSUE [{issue.code}] {issue.path}", file=sys.stderr)
                return 1
            print("Archive verification successful: 0 issues found.")
            return 0

        if args.subcommand == "restore-check":
            manifest_text = args.manifest.read_text(encoding="utf-8")
            manifest = Manifest.from_json(manifest_text)
            report = restore_check(args.archive, manifest, args.dest, limits=Limits())
            if not report.ok:
                for issue in report.issues:
                    print(f"ISSUE [{issue.code}] {issue.path}", file=sys.stderr)
                return 1
            print("Restore check successful: all files safely restored and verified.")
            return 0

    except BackupError as err:
        print(f"ERROR: {err}", file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"UNEXPECTED ERROR: {exc}", file=sys.stderr)
        return 2

    return 0


if __name__ == "__main__":
    sys.exit(main())
