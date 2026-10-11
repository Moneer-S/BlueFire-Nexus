"""Opt-in atomic publication retains strict ordinary-file admission."""

import os

import pytest

from bluefire.runner_private_files import _PinnedPrivateDirectory
from tests_platform.test_verified_private_directory import prepared


def test_atomic_create_and_promotion_keep_one_link_and_do_not_overwrite(tmp_path):
    root = prepared(tmp_path)
    with _PinnedPrivateDirectory(root) as directory:
        directory.create("pending", b"original", maximum=128, atomic_no_replace=True)
        assert (root / "pending").stat().st_nlink == 1
        identity = directory.file_identity("pending", maximum=128)
        with pytest.raises(OSError):
            directory.promote(
                "pending",
                "record.json",
                maximum=128,
                expected=b"original",
                permissions_already_private=True,
                atomic_no_replace=True,
            )
        assert directory.read("pending", maximum=128) == b"original"
        assert directory.read("record.json", maximum=128) == b'{"safe":true}'
        directory.promote(
            "pending",
            "published",
            maximum=128,
            expected=b"original",
            permissions_already_private=True,
            atomic_no_replace=True,
        )
        assert directory.file_identity("published", maximum=128) == identity
        assert (root / "published").stat().st_nlink == 1
        assert not directory.has_name("pending")


@pytest.mark.skipif(os.name == "nt", reason="POSIX atomic implementation")
def test_atomic_publication_never_falls_back_to_link_or_overwriting_rename(tmp_path, monkeypatch):
    root = prepared(tmp_path)

    def forbidden(*_args, **_kwargs):
        pytest.fail("atomic publication must not create a hardlink or overwrite")

    monkeypatch.setattr(os, "link", forbidden)
    monkeypatch.setattr(os, "rename", forbidden)
    monkeypatch.setattr(os, "replace", forbidden)
    with _PinnedPrivateDirectory(root, verify_permissions_only=True) as directory:
        directory.create("pending", b"value", maximum=16, atomic_no_replace=True)
        directory.promote(
            "pending",
            "published",
            maximum=16,
            expected=b"value",
            permissions_already_private=True,
            atomic_no_replace=True,
        )
        assert directory.read("published", maximum=16) == b"value"


@pytest.mark.parametrize("mode", [None, 0, 1, "true"])
def test_invalid_atomic_mode_refuses_before_creating_or_moving_files(tmp_path, mode):
    root = prepared(tmp_path)
    before = {path.name: path.read_bytes() for path in root.iterdir()}
    with _PinnedPrivateDirectory(root, verify_permissions_only=True) as directory:
        with pytest.raises(OSError, match="mode"):
            directory.create("new", b"value", maximum=16, atomic_no_replace=mode)
        with pytest.raises(OSError, match="mode"):
            directory.promote(
                "record.json", "new", maximum=128, expected=b'{"safe":true}', atomic_no_replace=mode
            )
    assert {path.name: path.read_bytes() for path in root.iterdir()} == before
