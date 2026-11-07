"""Behavior tests for the public API of backup_verifier."""

from __future__ import annotations

import pytest

import backup_verifier


def test_normalize_trims_and_lowercases() -> None:
    assert backup_verifier.normalize("  Hello World ") == "hello world"


@pytest.mark.parametrize("value", ["", "   ", "\t\n"])
def test_normalize_rejects_blank_input(value: str) -> None:
    with pytest.raises(ValueError, match="must not be empty"):
        backup_verifier.normalize(value)


def test_version_is_semver() -> None:
    parts = backup_verifier.__version__.split(".")
    assert len(parts) == 3
    assert all(part.isdigit() for part in parts)
