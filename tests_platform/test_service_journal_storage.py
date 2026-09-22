"""Actual permission admission precedes SQLite writes; shared histories stay intact."""

import ctypes
import os
import stat
import subprocess
import sys

import pytest

from bluefire import windows_owner_acl as acl
from bluefire.contracts import ContractError
from bluefire.tool_adapters import service_journal as journal_module
from bluefire.tool_adapters.service_journal import ServiceIntentJournal
from bluefire.tool_adapters.service_journal_storage import _check_private
from tests_platform import test_service_journal as fixtures

private_test_parent = fixtures.private_test_parent
reserved = fixtures.reserved
identity = fixtures.identity
identity_data = fixtures.identity_data


def _share(path, *, directory):
    if os.name != "nt":
        path.chmod(0o755 if directory else 0o644)
        return
    descriptor = acl._windows_open_descriptor(
        path, directory=directory, write_dac=True, share_write=True
    )
    advapi32, kernel32 = acl._configure_apis()
    flags = "OICI" if directory else ""
    seed = acl._converted_descriptor(
        advapi32, f"D:P(A;{flags};FA;;;{acl.current_user_sid()})(A;{flags};FR;;;WD)"
    )
    try:
        assert (
            advapi32.SetSecurityInfo(
                ctypes.c_void_p(acl._handle_from_descriptor(descriptor)),
                acl._SE_FILE_OBJECT,
                acl._DACL_SECURITY_INFORMATION | acl._PROTECTED_DACL_SECURITY_INFORMATION,
                None,
                None,
                acl._descriptor_dacl(advapi32, seed),
                None,
            )
            == 0
        )
    finally:
        kernel32.LocalFree(seed)
        os.close(descriptor)


def test_secure_file_exists_before_sqlite_connect(tmp_path, monkeypatch):
    path = tmp_path / "journal.sqlite3"
    original = journal_module.sqlite3.connect
    seen = []

    def checked_connect(*args, **kwargs):
        _check_private(path, directory=False)
        assert args[0].endswith("?mode=rw") and kwargs["uri"] is True
        seen.append(path.read_bytes())
        return original(*args, **kwargs)

    monkeypatch.setattr(journal_module.sqlite3, "connect", checked_connect)
    ServiceIntentJournal(path)
    assert seen == [b""]


@pytest.mark.parametrize("directory", [False, True])
def test_shared_storage_is_refused_without_repair(reserved, directory):
    path, journal, row = reserved
    before = path.read_bytes()
    target = path.parent if directory else path
    _share(target, directory=directory)
    for operation in (
        lambda: journal.get(row["identity_digest"]),
        lambda: ServiceIntentJournal(path),
    ):
        with pytest.raises(ContractError):
            operation()
        assert path.read_bytes() == before
        with pytest.raises((OSError, acl.WindowsOwnerAclError)):
            _check_private(target, directory=directory)


def test_shared_parent_refused_before_file_creation(tmp_path):
    _share(tmp_path, directory=True)
    path = tmp_path / "new.sqlite3"
    with pytest.raises(ContractError):
        ServiceIntentJournal(path)
    assert not path.exists()


def test_database_replacement_refused_by_existing_instance(reserved):
    path, journal, row = reserved
    backup = path.with_suffix(".retained")
    path.rename(backup)
    ServiceIntentJournal(path)
    before = backup.read_bytes()
    with pytest.raises(ContractError):
        journal.get(row["identity_digest"])
    assert backup.read_bytes() == before


def test_missing_database_not_recreated(reserved):
    path, journal, row = reserved
    path.rename(path.with_suffix(".retained"))
    with pytest.raises(ContractError):
        journal.get(row["identity_digest"])
    assert not path.exists()


def test_hardlinked_history_refused(reserved):
    path, journal, row = reserved
    link = path.with_suffix(".link")
    os.link(path, link)
    before = path.read_bytes()
    with pytest.raises(ContractError):
        ServiceIntentJournal(path)
    with pytest.raises(ContractError):
        journal.get(row["identity_digest"])
    assert link.read_bytes() == before


@pytest.mark.skipif(os.name == "nt", reason="POSIX owner and mode contract")
@pytest.mark.parametrize("directory", [False, True])
def test_foreign_posix_owner_refused(reserved, monkeypatch, directory):
    path, journal, row = reserved
    from bluefire.tool_adapters import service_journal_storage as storage

    original = storage.os.fstat
    target = path.parent if directory else path
    identity = target.stat().st_ino

    def foreign_stat(fd):
        result = original(fd)
        if result.st_ino == identity:
            fields = list(result)
            fields[4] = result.st_uid + 1
            return os.stat_result(fields)
        return result

    monkeypatch.setattr(storage.os, "fstat", foreign_stat)
    with pytest.raises(ContractError):
        ServiceIntentJournal(path)


@pytest.mark.skipif(os.name == "nt", reason="POSIX creation under permissive umask")
def test_permissive_umask_never_creates_shared_database(tmp_path):
    path = tmp_path / "journal.sqlite3"
    script = "import os,sys; from pathlib import Path; from bluefire.tool_adapters.service_journal import ServiceIntentJournal; os.umask(0); ServiceIntentJournal(Path(sys.argv[1]))"
    result = subprocess.run(
        [sys.executable, "-c", script, str(path)], capture_output=True, text=True, timeout=20
    )
    assert result.returncode == 0, result.stderr
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


@pytest.mark.skipif(os.name != "nt", reason="Native Windows DACL contract")
def test_existing_private_windows_storage_never_rewrites_acl(reserved, monkeypatch):
    path, _, row = reserved
    advapi32, kernel32 = acl._configure_apis()

    def forbidden(*args):
        raise AssertionError("existing journal ACL must be checked without repair")

    monkeypatch.setattr(advapi32, "SetSecurityInfo", forbidden)
    monkeypatch.setattr(acl, "_configure_apis", lambda: (advapi32, kernel32))
    assert ServiceIntentJournal(path).get(row["identity_digest"]) == row


@pytest.mark.skipif(os.name != "nt", reason="Native Windows owner contract")
def test_foreign_windows_owner_is_refused(reserved, monkeypatch):
    path, _, _ = reserved
    monkeypatch.setattr(
        acl, "_current_token_sids", lambda: ("S-1-5-21-1-2-3-1234", "S-1-5-21-1-2-3-1234")
    )
    with pytest.raises(ContractError):
        ServiceIntentJournal(path)


def test_permission_change_before_commit_rolls_back(reserved):
    path, journal, row = reserved
    with pytest.raises(ContractError):
        with journal._transaction() as connection:
            connection.execute("DELETE FROM service_intents")
            _share(path, directory=False)
    # Restore only this test-owned fixture to inspect the retained history.
    if os.name == "nt":
        acl.apply_owner_private_acl_path(path, directory=False)
    else:
        path.chmod(0o600)
    assert ServiceIntentJournal(path).get(row["identity_digest"]) == row


@pytest.mark.skipif(os.name == "nt", reason="POSIX symbolic-link fixture")
def test_symbolic_link_path_refused(reserved):
    path, _, _ = reserved
    link = path.with_suffix(".symlink")
    link.symlink_to(path)
    before = path.read_bytes()
    with pytest.raises(ContractError):
        ServiceIntentJournal(link)
    assert path.read_bytes() == before
