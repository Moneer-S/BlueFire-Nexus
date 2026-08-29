from __future__ import annotations

import os
from pathlib import Path

import pytest

import bluefire.runner_trust as runner_trust
import bluefire.windows_owner_acl as owner_acl
from bluefire.runner_client import _windows_open_descriptor
from bluefire.runner_trust import RunnerTrustError, _PinnedDirectory
from bluefire.windows_owner_acl import (
    WindowsOwnerAclError,
    apply_owner_private_acl,
    apply_owner_private_acl_handle,
    current_owner_sid,
)

pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows DACL contract")


def _different_sid(*excluded: str) -> str:
    return next(
        candidate for candidate in ("S-1-5-18", "S-1-5-19", "S-1-5-20") if candidate not in excluded
    )


@pytest.mark.parametrize(
    ("descriptor", "directory"),
    [
        (-1, False),
        (True, False),
        (0, 1),
    ],
)
def test_owner_acl_rejects_invalid_inputs(
    descriptor: int,
    directory: bool,
) -> None:
    with pytest.raises(WindowsOwnerAclError):
        apply_owner_private_acl(descriptor, directory=directory)


def test_owner_acl_routes_distinct_token_user_and_default_owner(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    access_sid = "S-1-5-21-1-2-3-1001"
    owner_sid = "S-1-5-32-544"
    observed: dict[str, object] = {}
    monkeypatch.setattr(
        owner_acl,
        "_current_token_sids",
        lambda: (access_sid, owner_sid),
    )

    def capture(
        descriptor: int,
        *,
        access_sid: str,
        owner_sid: str,
        directory: bool,
    ) -> None:
        observed.update(
            descriptor=descriptor,
            access_sid=access_sid,
            owner_sid=owner_sid,
            directory=directory,
        )

    monkeypatch.setattr(owner_acl, "_apply_owner_private_acl", capture)

    apply_owner_private_acl(37, directory=True)

    assert observed == {
        "descriptor": 37,
        "access_sid": access_sid,
        "owner_sid": owner_sid,
        "directory": True,
    }


def test_owner_acl_is_applied_and_verified_on_the_pinned_file_handle(
    tmp_path: Path,
) -> None:
    import msvcrt

    path = tmp_path / "payload.bin"
    path.write_bytes(b"owner-bound")
    descriptor = _windows_open_descriptor(
        path,
        directory=False,
        write=True,
        write_dac=True,
    )
    try:
        apply_owner_private_acl_handle(msvcrt.get_osfhandle(descriptor), directory=False)
        assert os.fstat(descriptor).st_size == len(b"owner-bound")
    finally:
        os.close(descriptor)


def test_owner_acl_accepts_an_existing_access_sid_owner_when_token_owner_differs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "existing-user-owner.bin"
    path.write_bytes(b"owner-bound")
    descriptor = _windows_open_descriptor(
        path,
        directory=False,
        write=True,
        write_dac=True,
    )
    try:
        observed_owner_sid = current_owner_sid()
        different_default_owner_sid = _different_sid(observed_owner_sid)
        monkeypatch.setattr(
            owner_acl,
            "_current_token_sids",
            lambda: (observed_owner_sid, different_default_owner_sid),
        )

        apply_owner_private_acl(descriptor, directory=False)

        assert os.fstat(descriptor).st_size == len(b"owner-bound")
    finally:
        os.close(descriptor)


def test_owner_acl_refuses_a_well_formed_nonowner_sid_without_changing_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "owner-check.bin"
    path.write_bytes(b"unchanged")
    descriptor = _windows_open_descriptor(
        path,
        directory=False,
        write=True,
        write_dac=True,
    )
    try:
        before = os.fstat(descriptor)
        actual_owner_sid = current_owner_sid()
        nonowner_access_sid = _different_sid(actual_owner_sid)
        nonowner_default_sid = _different_sid(actual_owner_sid, nonowner_access_sid)
        monkeypatch.setattr(
            owner_acl,
            "_current_token_sids",
            lambda: (nonowner_access_sid, nonowner_default_sid),
        )
        with pytest.raises(
            WindowsOwnerAclError,
            match="owner verification failed",
        ):
            apply_owner_private_acl(descriptor, directory=False)
        after = os.fstat(descriptor)
        assert (after.st_dev, after.st_ino, after.st_size) == (
            before.st_dev,
            before.st_ino,
            before.st_size,
        )
    finally:
        os.close(descriptor)


def test_owner_acl_is_applied_and_verified_on_the_pinned_directory_handle(
    tmp_path: Path,
) -> None:
    directory = tmp_path / "private"
    directory.mkdir()
    descriptor = _windows_open_descriptor(
        directory,
        directory=True,
        write_dac=True,
    )
    try:
        apply_owner_private_acl(descriptor, directory=True)
        assert os.path.samestat(os.fstat(descriptor), directory.stat())
    finally:
        os.close(descriptor)


def test_owner_bound_read_refuses_an_existing_writer(tmp_path: Path) -> None:
    directory = tmp_path / "private-read"
    directory.mkdir()
    path = directory / "payload.bin"
    path.write_bytes(b"owner-bound")
    writer = _windows_open_descriptor(
        path,
        directory=False,
        write=True,
        write_dac=True,
    )
    try:
        with _PinnedDirectory(directory, private=True) as pinned:
            with pytest.raises(RunnerTrustError):
                pinned.read_with_identity(path.name, maximum=1024, exclusive=True)
    finally:
        os.close(writer)


def test_owner_bound_read_denies_named_replacement_while_handle_is_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    directory = tmp_path / "private-swap"
    directory.mkdir()
    path = directory / "payload.bin"
    replacement = directory / "replacement.bin"
    path.write_bytes(b"owner-bound")
    replacement.write_bytes(b"replacement")
    original_read = runner_trust._read_descriptor_bounded
    replacement_errors: list[OSError] = []

    def attempt_replacement(descriptor: int, maximum: int) -> bytes:
        payload = original_read(descriptor, maximum)
        try:
            os.replace(replacement, path)
        except OSError as exc:
            replacement_errors.append(exc)
        return payload

    monkeypatch.setattr(runner_trust, "_read_descriptor_bounded", attempt_replacement)

    with _PinnedDirectory(directory, private=True) as pinned:
        payload, identity, snapshot = pinned.read_with_identity(
            path.name,
            maximum=1024,
            exclusive=True,
        )

    assert payload == b"owner-bound"
    assert all(identity)
    assert snapshot[3] == len(payload)
    assert len(replacement_errors) == 1
    assert path.read_bytes() == b"owner-bound"
    assert replacement.read_bytes() == b"replacement"
