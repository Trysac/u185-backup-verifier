"""Unit tests for backup_verifier covering all acceptance criteria and edge cases."""

from __future__ import annotations

import hashlib
import io
import tarfile
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from backup_verifier import (
    BackupError,
    BackupEvent,
    BackupInfo,
    Entry,
    Issue,
    Limits,
    Manifest,
    Report,
    check_freshness,
    create_manifest,
    is_unsafe_path,
    restore_check,
    verify_archive,
)
from backup_verifier.__main__ import main


def test_create_manifest_and_json_roundtrip(tmp_path: Path) -> None:
    # Criterion 1: create_manifest(root) for 'a.txt' = b'hello' and 'sub/b.bin' = b''
    (tmp_path / "a.txt").write_bytes(b"hello")
    sub = tmp_path / "sub"
    sub.mkdir()
    (sub / "b.bin").write_bytes(b"")

    manifest = create_manifest(tmp_path)
    expected = (
        Entry(
            path="a.txt",
            size=5,
            sha256="2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
        ),
        Entry(
            path="sub/b.bin",
            size=0,
            sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ),
    )
    assert manifest.entries == expected
    json_str = manifest.to_json()
    parsed = Manifest.from_json(json_str)
    assert parsed == manifest


def test_verify_tar_gz_and_zip(tmp_path: Path) -> None:
    # Criterion 2: verify_archive of 'b.tar.gz' and 'b.zip' built from those files returns Report(ok=True, issues=())
    file_a = tmp_path / "a.txt"
    file_a.write_bytes(b"hello")
    sub = tmp_path / "sub"
    sub.mkdir()
    file_b = sub / "b.bin"
    file_b.write_bytes(b"")

    manifest = create_manifest(tmp_path)

    tar_path = tmp_path / "b.tar.gz"
    with tarfile.open(tar_path, "w:gz") as tf:
        tf.add(file_a, arcname="a.txt")
        tf.add(file_b, arcname="sub/b.bin")

    rep_tar = verify_archive(tar_path, manifest)
    assert rep_tar == Report(ok=True, issues=())

    zip_path = tmp_path / "b.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.write(file_a, arcname="a.txt")
        zf.write(file_b, arcname="sub/b.bin")

    rep_zip = verify_archive(zip_path, manifest)
    assert rep_zip == Report(ok=True, issues=())


def test_mismatch_missing_extra_and_size_mismatch(tmp_path: Path) -> None:
    # Criterion 3:
    # An archive lacking 'sub/b.bin', adding 'c.txt' and holding a.txt = b'hellO'
    # gives issues [Issue('hash_mismatch', 'a.txt'), Issue('extra', 'c.txt'), Issue('missing', 'sub/b.bin')]
    # a.txt = b'hello!' gives 'size_mismatch' and no hash check
    manifest_entries = (
        Entry(
            path="a.txt",
            size=5,
            sha256="2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
        ),
        Entry(
            path="sub/b.bin",
            size=0,
            sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ),
    )
    manifest = Manifest(entries=manifest_entries)

    tar_path = tmp_path / "archive1.tar"
    with tarfile.open(tar_path, "w") as tf:
        ti_a = tarfile.TarInfo("a.txt")
        content_a = b"hellO"
        ti_a.size = len(content_a)
        tf.addfile(ti_a, io.BytesIO(content_a))

        ti_c = tarfile.TarInfo("c.txt")
        content_c = b"extra content"
        ti_c.size = len(content_c)
        tf.addfile(ti_c, io.BytesIO(content_c))

    report = verify_archive(tar_path, manifest)
    expected_issues = (
        Issue("hash_mismatch", "a.txt"),
        Issue("extra", "c.txt"),
        Issue("missing", "sub/b.bin"),
    )
    assert report.issues == expected_issues
    assert not report.ok

    # Test size mismatch
    tar_path2 = tmp_path / "archive2.tar"
    with tarfile.open(tar_path2, "w") as tf:
        ti_a2 = tarfile.TarInfo("a.txt")
        content_a2 = b"hello!"
        ti_a2.size = len(content_a2)
        tf.addfile(ti_a2, io.BytesIO(content_a2))

    report2 = verify_archive(tar_path2, manifest)
    # a.txt = b'hello!' gives 'size_mismatch' and no hash check (sub/b.bin is also missing)
    a_issues = [i for i in report2.issues if i.path == "a.txt"]
    assert a_issues == [Issue("size_mismatch", "a.txt")]


def test_unsafe_paths(tmp_path: Path) -> None:
    # Criterion 4:
    # Members '../evil', '/abs', 'a/../../x', 'C:x', 'dir\x' and 'aux.txt' each give Issue('unsafe_path', name) on every OS,
    # and restore_check writes none of them
    unsafe_names = ["../evil", "/abs", "a/../../x", "C:x", "dir\\x", "aux.txt"]
    for name in unsafe_names:
        assert is_unsafe_path(name)

    tar_path = tmp_path / "unsafe.tar"
    with tarfile.open(tar_path, "w") as tf:
        for name in unsafe_names:
            ti = tarfile.TarInfo(name)
            data = b"danger"
            ti.size = len(data)
            tf.addfile(ti, io.BytesIO(data))

    manifest = Manifest(entries=())
    rep = verify_archive(tar_path, manifest)
    rep_unsafe_names = [i.path for i in rep.issues if i.code == "unsafe_path"]
    for name in unsafe_names:
        assert name in rep_unsafe_names

    dest = tmp_path / "empty_dest"
    dest.mkdir()
    restore_rep = restore_check(tar_path, manifest, dest)
    assert not restore_rep.ok
    # None of the unsafe members are written
    assert list(dest.iterdir()) == []


def test_unsupported_members_and_duplicates(tmp_path: Path) -> None:
    # Criterion 5:
    # A symlink member 'link' and a hardlink member each give 'unsupported_member' and are never created;
    # a tar containing 'a.txt' twice gives 'duplicate_member'
    tar_path = tmp_path / "special.tar"
    with tarfile.open(tar_path, "w") as tf:
        ti_sym = tarfile.TarInfo("link")
        ti_sym.type = tarfile.SYMTYPE
        ti_sym.linkname = "target.txt"
        tf.addfile(ti_sym)

        ti_lnk = tarfile.TarInfo("hardlink")
        ti_lnk.type = tarfile.LNKTYPE
        ti_lnk.linkname = "target.txt"
        tf.addfile(ti_lnk)

        # Add a.txt twice
        ti1 = tarfile.TarInfo("a.txt")
        ti1.size = 3
        tf.addfile(ti1, io.BytesIO(b"foo"))

        ti2 = tarfile.TarInfo("a.txt")
        ti2.size = 3
        tf.addfile(ti2, io.BytesIO(b"bar"))

    manifest = Manifest(
        entries=(
            Entry("a.txt", 3, "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae"),
        )
    )
    report = verify_archive(tar_path, manifest)
    issue_codes = {(i.code, i.path) for i in report.issues}
    assert ("unsupported_member", "link") in issue_codes
    assert ("unsupported_member", "hardlink") in issue_codes
    assert ("duplicate_member", "a.txt") in issue_codes

    dest = tmp_path / "dest_special"
    dest.mkdir()
    res_report = restore_check(tar_path, manifest, dest)
    assert not (dest / "link").exists()
    assert not (dest / "hardlink").exists()
    assert not res_report.ok


def test_limits_exceeded(tmp_path: Path) -> None:
    # Criterion 6:
    # With max_total_bytes=10 an archive with an 11-byte member raises BackupError with code 'limit_exceeded'
    # (10 bytes accepted), counted while reading in 1 MiB chunks; max_members=2 with three members raises the same code
    tar_path = tmp_path / "big_member.tar"
    with tarfile.open(tar_path, "w") as tf:
        ti = tarfile.TarInfo("eleven.txt")
        ti.size = 11
        tf.addfile(ti, io.BytesIO(b"12345678901"))

    manifest = Manifest(entries=(Entry("eleven.txt", 11, "dummy"),))
    with pytest.raises(BackupError) as exc_info:
        verify_archive(tar_path, manifest, limits=Limits(max_total_bytes=10))
    assert exc_info.value.code == "limit_exceeded"

    # max_members=2 with three members
    tar_path3 = tmp_path / "three_members.tar"
    with tarfile.open(tar_path3, "w") as tf:
        for i in range(3):
            ti = tarfile.TarInfo(f"f{i}.txt")
            ti.size = 1
            tf.addfile(ti, io.BytesIO(b"x"))

    with pytest.raises(BackupError) as exc_info2:
        verify_archive(tar_path3, Manifest(entries=()), limits=Limits(max_members=2))
    assert exc_info2.value.code == "limit_exceeded"

    # Also test member limit
    with pytest.raises(BackupError) as exc_info3:
        verify_archive(tar_path, manifest, limits=Limits(max_member_bytes=10))
    assert exc_info3.value.code == "limit_exceeded"


def test_restore_check_empty_dest_and_errors(tmp_path: Path) -> None:
    # Criterion 7:
    # restore_check(archive, manifest, dest) into an empty directory returns ok=True and the restored bytes equal the originals;
    # a dest containing a file raises code 'dest_not_empty'; b'not an archive' raises code 'unreadable_archive'
    content = b"original payload"
    hasher = hashlib.sha256(content).hexdigest()
    tar_path = tmp_path / "good.tar"
    with tarfile.open(tar_path, "w") as tf:
        ti = tarfile.TarInfo("nested/dir/data.bin")
        ti.size = len(content)
        tf.addfile(ti, io.BytesIO(content))

    manifest = Manifest(entries=(Entry("nested/dir/data.bin", len(content), hasher),))
    dest = tmp_path / "restore_target"
    dest.mkdir()

    rep = restore_check(tar_path, manifest, dest)
    assert rep.ok
    assert (dest / "nested" / "dir" / "data.bin").read_bytes() == content

    # Dest not empty
    with pytest.raises(BackupError) as exc_info:
        restore_check(tar_path, manifest, dest)
    assert exc_info.value.code == "dest_not_empty"

    # Unreadable archive
    not_archive = tmp_path / "corrupt.bin"
    not_archive.write_bytes(b"not an archive")
    dest2 = tmp_path / "empty2"
    dest2.mkdir()
    with pytest.raises(BackupError) as exc_info2:
        restore_check(not_archive, manifest, dest2)
    assert exc_info2.value.code == "unreadable_archive"


def test_freshness_checks() -> None:
    # Criterion 8:
    # check_freshness(backups, now=datetime(2026, 11, 6, 12, 0, tzinfo=timezone.utc), max_age=timedelta(hours=24), min_count=1)
    # returns [Issue('stale', 'b1')] when the newest b1 was created 2026-11-05T11:59Z and [] when created 2026-11-05T12:00Z
    now = datetime(2026, 11, 6, 12, 0, tzinfo=timezone.utc)
    max_age = timedelta(hours=24)

    stale_b = [BackupInfo("b1", datetime(2026, 11, 5, 11, 59, tzinfo=timezone.utc))]
    res_stale = check_freshness(stale_b, now=now, max_age=max_age, min_count=1)
    assert res_stale == [Issue("stale", "b1")]

    fresh_b = [BackupInfo("b1", datetime(2026, 11, 5, 12, 0, tzinfo=timezone.utc))]
    res_fresh = check_freshness(fresh_b, now=now, max_age=max_age, min_count=1)
    assert res_fresh == []


def test_freshness_too_few_and_invalid_manifest() -> None:
    # Criterion 9:
    # check_freshness with min_count=3 and two backups returns Issue('too_few', '*');
    # a naive now raises code 'invalid_option';
    # Manifest.from_json with a 63-character sha256 raises code 'invalid_manifest'
    now = datetime(2026, 11, 6, 12, 0, tzinfo=timezone.utc)
    backups = [
        BackupInfo("b1", datetime(2026, 11, 6, 11, 0, tzinfo=timezone.utc)),
        BackupInfo("b2", datetime(2026, 11, 6, 11, 30, tzinfo=timezone.utc)),
    ]
    issues = check_freshness(backups, now=now, max_age=timedelta(hours=24), min_count=3)
    assert issues == [Issue("too_few", "*")]

    # Naive now
    naive_now = datetime(2026, 11, 6, 12, 0)
    with pytest.raises(BackupError) as exc_naive:
        check_freshness(backups, now=naive_now, max_age=timedelta(hours=24))
    assert exc_naive.value.code == "invalid_option"

    # 63-character sha256 in manifest json
    bad_json = """{
        "format": "backup-manifest/1",
        "entries": [
            {"path": "a.txt", "size": 5, "sha256": "123456789012345678901234567890123456789012345678901234567890123"}
        ]
    }"""
    with pytest.raises(BackupError) as exc_man:
        Manifest.from_json(bad_json)
    assert exc_man.value.code == "invalid_manifest"


def test_events_and_cli(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # Criterion 10:
    # on_event receives BackupEvent('member_checked', path, None) and BackupEvent('issue', path, code) records
    # that never contain file bytes; CLI main(['verify', 'b.tar.gz', 'm.json']) returns 1 with issues, 0 when ok and 2 for BackupError
    events: list[BackupEvent] = []

    tar_path = tmp_path / "b.tar.gz"
    with tarfile.open(tar_path, "w:gz") as tf:
        ti = tarfile.TarInfo("f.txt")
        ti.size = 4
        tf.addfile(ti, io.BytesIO(b"test"))

    manifest = Manifest(
        entries=(
            Entry("f.txt", 4, "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"),
        )
    )
    rep = verify_archive(tar_path, manifest, on_event=events.append)
    assert rep.ok
    assert len(events) == 1
    assert events[0] == BackupEvent("member_checked", "f.txt", None)

    # CLI checks
    m_file = tmp_path / "m.json"
    m_file.write_text(manifest.to_json(), encoding="utf-8")

    # 1. OK verify: exit 0
    assert main(["verify", str(tar_path), str(m_file)]) == 0

    # 2. Issues verify: exit 1
    empty_manifest = tmp_path / "empty_m.json"
    empty_manifest.write_text(Manifest(entries=()).to_json(), encoding="utf-8")
    assert main(["verify", str(tar_path), str(empty_manifest)]) == 1

    # 3. BackupError: exit 2
    assert main(["verify", str(tmp_path / "nonexistent.tar"), str(m_file)]) == 2

    # Test CLI manifest subcommand
    src_dir = tmp_path / "src_dir"
    src_dir.mkdir()
    (src_dir / "hello.txt").write_text("hi")
    out_manifest = tmp_path / "generated.json"
    assert main(["manifest", str(src_dir), "-o", str(out_manifest)]) == 0
    assert out_manifest.exists()

    # Test CLI restore-check subcommand
    dest_dir = tmp_path / "restored_cli"
    dest_dir.mkdir()
    assert main(["restore-check", str(tar_path), str(m_file), "--dest", str(dest_dir)]) == 0
    assert (dest_dir / "f.txt").exists()


def test_additional_edge_cases(tmp_path: Path) -> None:
    # Unsafe paths variants: NUL, root, drive, reserved
    assert is_unsafe_path("foo\x00bar")
    assert is_unsafe_path("/root/file")
    assert is_unsafe_path("CON.txt")
    assert is_unsafe_path("dir/com1")
    assert is_unsafe_path("space /file")
    assert is_unsafe_path("dot./file")
    assert is_unsafe_path("")

    # Manifest validation errors
    with pytest.raises(BackupError) as exc1:
        Manifest.from_json("invalid json")
    assert exc1.value.code == "invalid_manifest"

    with pytest.raises(BackupError) as exc2:
        Manifest.from_json("[]")
    assert exc2.value.code == "invalid_manifest"

    with pytest.raises(BackupError) as exc3:
        Manifest.from_json('{"format": "other"}')
    assert exc3.value.code == "invalid_manifest"

    with pytest.raises(BackupError) as exc4:
        Manifest.from_json('{"format": "backup-manifest/1", "entries": "none"}')
    assert exc4.value.code == "invalid_manifest"

    with pytest.raises(BackupError) as exc5:
        Manifest.from_json('{"format": "backup-manifest/1", "entries": ["bad"]}')
    assert exc5.value.code == "invalid_manifest"

    with pytest.raises(BackupError) as exc6:
        Manifest.from_json(
            '{"format": "backup-manifest/1", "entries": [{"path": "/abs", "size": 0, "sha256": ""}]}'
        )
    assert exc6.value.code == "invalid_manifest"

    # Zip archive with directory entry and extra file
    zip_path = tmp_path / "test.zip"
    item_content = b"contents"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("folder/", "")
        zf.writestr("folder/item.txt", item_content)

    manifest = Manifest(
        entries=(
            Entry(
                "folder/item.txt",
                len(item_content),
                hashlib.sha256(item_content).hexdigest(),
            ),
        )
    )
    report = verify_archive(zip_path, manifest)
    assert report.ok

    # create_manifest on non-dir
    non_dir = tmp_path / "not_a_dir"
    non_dir.write_text("hi")
    with pytest.raises(BackupError) as exc7:
        create_manifest(non_dir)
    assert exc7.value.code == "invalid_option"

    # BackupError str format
    err = BackupError("dest_not_empty", "custom message")
    assert str(err) == "[dest_not_empty] custom message"
