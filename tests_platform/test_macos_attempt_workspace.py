"""Fake POSIX descriptors only: no native directory, file or account effects."""

import errno
import os
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest

from bluefire import evidence
from bluefire import macos_attempt_workspace as workspace
from bluefire.util import content_hash

ATTEMPT = "attempt-" + "a" * 32
LEASE = "sha256:" + "b" * 64
COMPILED = "sha256:" + "c" * 64


@pytest.fixture
def posix(monkeypatch):
    root = Path("/synthetic/original-attempt").absolute()
    state = {
        "root": root,
        "inode": 11,
        "mtime": 1,
        "entries": [],
        "fds": {},
        "closed": [],
        "scans": [],
        "opens": [],
        "next_fd": 100,
        "pid": 701,
        "symlink": None,
        "on_scan": None,
        "scan_error": None,
        "fstat_error": None,
    }
    observers = []

    def open_directory(path, flags, *, dir_fd=None):
        expected = 8 | 16 | 32
        assert flags == expected
        target = Path(path) if dir_fd is None else state["fds"][dir_fd][0] / path
        state["opens"].append(target)
        if target == state["symlink"]:
            raise OSError(errno.ELOOP, "fake symlink refused")
        descriptor = state["next_fd"]
        state["next_fd"] += 1
        state["fds"][descriptor] = (target, state["inode"] if target == root else 2)
        return descriptor

    def fstat(descriptor):
        if state["fstat_error"] is not None:
            raise state["fstat_error"]
        _, inode = state["fds"][descriptor]
        return SimpleNamespace(
            st_mode=stat.S_IFDIR | 0o700,
            st_dev=5,
            st_ino=inode,
            st_mtime_ns=state["mtime"],
            st_ctime_ns=state["mtime"],
        )

    def close(descriptor):
        assert descriptor in state["fds"]
        state["closed"].append(descriptor)
        del state["fds"][descriptor]

    class Entries:
        def __enter__(self):
            if state["scan_error"] is not None:
                raise state["scan_error"]
            callback = state["on_scan"]
            if callback is not None:
                callback()
            return iter(state["entries"])

        def __exit__(self, *_):
            return False

    def scandir(descriptor):
        assert type(descriptor) is int
        assert state["fds"][descriptor][0] == root
        state["scans"].append(descriptor)
        return Entries()

    fake_os = SimpleNamespace(
        name="posix",
        path=os.path,
        O_RDONLY=0,
        O_NOFOLLOW=8,
        O_DIRECTORY=16,
        O_CLOEXEC=32,
        open=open_directory,
        close=close,
        fstat=fstat,
        scandir=scandir,
        supports_dir_fd={open_directory},
        supports_fd={scandir},
    )
    monkeypatch.setattr(evidence, "os", fake_os)
    monkeypatch.setattr(Path, "resolve", lambda self, strict=False: self.absolute())
    monkeypatch.setattr(workspace, "sys", SimpleNamespace(platform="darwin"))
    monkeypatch.setattr(workspace, "os", SimpleNamespace(name="posix", getpid=lambda: state["pid"]))
    original_init = evidence.SandboxObserver.__init__

    def retained_init(self, *args, **kwargs):
        original_init(self, *args, **kwargs)
        observers.append(self)

    monkeypatch.setattr(evidence.SandboxObserver, "__init__", retained_init)
    yield state
    for observer in observers:
        observer.close()
    assert state["fds"] == {}


def guard(posix, **changes):
    options = {"attempt_id": ATTEMPT, "lease_digest": LEASE, "compiled_digest": COMPILED}
    options.update(changes)
    return workspace.MacOSAttemptWorkspaceGuard(posix["root"], **options)


def test_original_descriptor_empty_inventory_binds_each_phase(posix):
    retained = guard(posix)
    identity = content_hash(
        {"schema_version": "bluefire.sandbox-directory-identity.v1", "device": 5, "inode": 11}
    )
    for phase in ("reserve", "pre_close", "post_close"):
        assert retained.attest(phase) == {
            "schema_version": workspace.EMPTY_WORKSPACE_SCHEMA,
            "attempt_id": ATTEMPT,
            "lease_digest": LEASE,
            "compiled_digest": COMPILED,
            "workspace_path_digest": content_hash({"sandbox_root": str(posix["root"])}),
            "workspace_identity_digest": identity,
            "phase": phase,
            "entry_count": 0,
            "state": "verified_empty",
        }
    assert len(posix["scans"]) == 4
    assert len(set(posix["scans"])) == 1
    retained.close()
    retained.close()
    with pytest.raises(workspace.MacOSAttemptWorkspaceError, match="closed"):
        retained.attest("post_close")


def test_repeated_phase_reenumerates_instead_of_reusing_attestation(posix):
    retained = guard(posix)
    retained.attest("reserve")
    posix["entries"] = ["unreported-entry"]
    with pytest.raises(evidence.EvidenceError, match="not stably empty"):
        retained.attest("reserve")
    assert len(posix["scans"]) == 3
    posix["entries"] = []
    with pytest.raises(workspace.MacOSAttemptWorkspaceError, match="closed"):
        retained.attest("reserve")


@pytest.mark.parametrize("entry", ["artifact.json", "symlink", "subdirectory", ".hidden"])
def test_any_entry_refuses_without_entry_reads_or_removal(posix, entry):
    posix["entries"] = [entry]
    with pytest.raises(evidence.EvidenceError, match="not stably empty"):
        guard(posix)
    assert posix["fds"] == {}
    assert len(posix["scans"]) == 1


def test_nonempty_enumeration_stops_at_first_entry(posix):
    class FirstEntryOnly:
        consumed = False

        def __iter__(self):
            return self

        def __next__(self):
            if self.consumed:
                pytest.fail("empty inventory consumed more than its first entry")
            self.consumed = True
            return "first-entry"

    posix["entries"] = FirstEntryOnly()
    with pytest.raises(evidence.EvidenceError, match="not stably empty"):
        guard(posix)
    assert posix["fds"] == {}


@pytest.mark.parametrize("when", ["before", "during"])
def test_root_replacement_before_or_during_scan_poisoned(posix, when):
    retained = guard(posix)
    retained.attest("reserve")
    scans = len(posix["scans"])
    if when == "before":
        posix["inode"] = 12
    else:
        posix["on_scan"] = lambda: posix.update(inode=12)
    with pytest.raises(evidence.EvidenceError, match="identity changed"):
        retained.attest("pre_close")
    assert len(posix["scans"]) == scans + (when == "during")
    assert posix["fds"] == {}


def test_mutation_during_descriptor_enumeration_refuses(posix):
    retained = guard(posix)
    posix["on_scan"] = lambda: posix.update(mtime=2)
    with pytest.raises(evidence.EvidenceError, match="not stably empty"):
        retained.attest("reserve")
    assert posix["fds"] == {}


def test_retained_descriptor_identity_change_refuses_before_scan(posix):
    retained = guard(posix)
    descriptor = posix["scans"][0]
    posix["fds"][descriptor] = (posix["root"], 12)
    with pytest.raises(evidence.EvidenceError, match="identity changed"):
        retained.attest("reserve")
    assert len(posix["scans"]) == 1
    assert posix["fds"] == {}


@pytest.mark.parametrize("parent", [False, True])
def test_initial_symlink_component_is_not_followed(posix, parent):
    posix["symlink"] = posix["root"].parent if parent else posix["root"]
    with pytest.raises(evidence.EvidenceError, match="unavailable or unsafe"):
        guard(posix)
    assert posix["scans"] == []
    assert posix["fds"] == {}


def test_unavailable_scan_poisoned_without_path_fallback(posix):
    retained = guard(posix)
    posix["scan_error"] = OSError("fake descriptor inventory unavailable")
    with pytest.raises(evidence.EvidenceError, match="inventory is unavailable"):
        retained.attest("reserve")
    assert posix["fds"] == {}
    assert all(type(value) is int for value in posix["scans"])


def test_lost_descriptor_refuses_without_path_only_fallback(posix):
    retained = guard(posix)
    posix["fstat_error"] = OSError(errno.EBADF, "fake descriptor lost")
    with pytest.raises(evidence.EvidenceError, match="identity changed"):
        retained.attest("reserve")
    assert len(posix["scans"]) == 1
    assert posix["fds"] == {}


def test_platform_without_descriptor_scandir_refuses(posix, monkeypatch):
    retained = guard(posix)
    monkeypatch.setattr(evidence.os, "supports_fd", set())
    with pytest.raises(evidence.EvidenceError, match="inventory is unavailable"):
        retained.attest("reserve")
    assert len(posix["scans"]) == 1
    assert posix["fds"] == {}


@pytest.mark.parametrize("operation", ["attest", "validate_binding"])
def test_fork_copy_refuses_before_inherited_lock_and_releases_descriptor(posix, operation):
    retained = guard(posix)

    class UnavailableInheritedLock:
        def __enter__(self):
            pytest.fail("fork copy attempted to acquire inherited lock")

    retained._lock = UnavailableInheritedLock()
    posix["pid"] += 1
    with pytest.raises(workspace.MacOSAttemptWorkspaceError, match="process is unavailable"):
        if operation == "attest":
            retained.attest("reserve")
        else:
            retained.validate_binding(
                posix["root"], attempt_id=ATTEMPT, lease_digest=LEASE, compiled_digest=COMPILED
            )
    assert len(posix["scans"]) == 1
    assert posix["fds"] == {}
    retained.close()


def test_binding_validation_preserves_original_pin_without_scan_or_phase_advance(posix):
    retained = guard(posix)
    scans = list(posix["scans"])
    retained.validate_binding(
        posix["root"], attempt_id=ATTEMPT, lease_digest=LEASE, compiled_digest=COMPILED
    )
    retained.validate_binding(
        str(posix["root"]), attempt_id=ATTEMPT, lease_digest=LEASE, compiled_digest=COMPILED
    )
    assert posix["scans"] == scans and retained._phase == -1
    assert retained.attest("reserve")["phase"] == "reserve"
    retained.validate_binding(
        posix["root"], attempt_id=ATTEMPT, lease_digest=LEASE, compiled_digest=COMPILED
    )
    assert retained._phase == 0 and len(posix["scans"]) == len(scans) + 1


@pytest.mark.parametrize("field", ["attempt", "lease", "compiled", "path"])
def test_changed_guard_binding_is_poisoned_without_advancing_inventory(posix, field):
    retained = guard(posix)
    options = {"attempt_id": ATTEMPT, "lease_digest": LEASE, "compiled_digest": COMPILED}
    root = posix["root"]
    if field == "attempt":
        options["attempt_id"] = "attempt-" + "d" * 32
    elif field == "lease":
        options["lease_digest"] = "sha256:" + "d" * 64
    elif field == "compiled":
        options["compiled_digest"] = "sha256:" + "d" * 64
    else:
        root = root / "replacement"
    with pytest.raises(workspace.MacOSAttemptWorkspaceError, match="binding changed"):
        retained.validate_binding(root, **options)
    assert retained._phase == -1 and len(posix["scans"]) == 1 and posix["fds"] == {}
    with pytest.raises(workspace.MacOSAttemptWorkspaceError, match="closed"):
        retained.attest("reserve")


def test_phase_order_and_no_serialized_proof_adoption(posix):
    retained = guard(posix)
    with pytest.raises(workspace.MacOSAttemptWorkspaceError, match="out of order"):
        retained.attest("post_close")
    proof = retained.attest("reserve")
    proof["workspace_identity_digest"] = "sha256:" + "f" * 64
    assert (
        retained.attest("reserve")["workspace_identity_digest"]
        != proof["workspace_identity_digest"]
    )
    retained.attest("pre_close")
    with pytest.raises(workspace.MacOSAttemptWorkspaceError, match="out of order"):
        retained.attest("reserve")
    retained.attest("post_close")
    assert not hasattr(workspace.MacOSAttemptWorkspaceGuard, "from_document")


@pytest.mark.parametrize(
    "field,value",
    [
        ("attempt_id", "attempt-unbound"),
        ("lease_digest", True),
        ("compiled_digest", "not-a-digest"),
    ],
)
def test_invalid_binding_refuses_before_any_descriptor_open(posix, field, value):
    with pytest.raises(workspace.MacOSAttemptWorkspaceError, match="binding is invalid"):
        guard(posix, **{field: value})
    assert posix["opens"] == []


@pytest.mark.parametrize("platform", ["win32", "linux"])
def test_non_darwin_refuses_before_any_descriptor_open(posix, monkeypatch, platform):
    monkeypatch.setattr(workspace, "sys", SimpleNamespace(platform=platform))
    with pytest.raises(workspace.MacOSAttemptWorkspaceError, match="inventory is unavailable"):
        guard(posix)
    assert posix["opens"] == []


def test_closed_observer_inventory_and_file_observation_both_refuse(posix):
    observer = evidence.SandboxObserver(posix["root"])
    observer.close()
    observer.close()
    with pytest.raises(evidence.EvidenceError, match="pin is unavailable"):
        observer.empty_posix_inventory()
    with pytest.raises(evidence.EvidenceError, match="pin is unavailable"):
        observer.observe_file(
            relative_path="never-read",
            run_id="run",
            step_id="step",
            behavior_id="behavior",
            action_id="action",
            runner_profile_id="profile",
        )
    assert posix["scans"] == []
