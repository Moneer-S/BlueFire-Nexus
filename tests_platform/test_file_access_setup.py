from __future__ import annotations

import copy
import json
import stat
import sys
from types import SimpleNamespace

import pytest

from bluefire import prepared_lab
from bluefire import prepared_lab_file_access as setup
from bluefire import prepared_lab_guest as guest
from bluefire import prepared_lab_runtime as runtime
from bluefire.file_access_contract import FileAccessContractError
from bluefire.file_access_enrollment import _root_owned, canonical_enrollment
from tests_platform.file_access_fixtures import binding


def enrollment():
    document = binding()
    resource = document["resource"]
    return {
        "schema_version": "bluefire.file-access-enrollment.v1",
        **{
            key: document[key]
            for key in (
                "enrollment_id",
                "resource_id",
                "resource_generation",
                "expires_at_ms",
                "worker",
            )
        },
        "issued_at_ms": 1_000_000,
        "runner_profile_id": "sandbox-execute.v1",
        "worker_source_digest": "sha256:" + "7" * 64,
        "root": {
            "path": resource["root"],
            "device": resource["root_device"],
            "inode": resource["root_inode"],
            "parent_device": resource["parent_device"],
            "parent_inode": resource["parent_inode"],
        },
        "limits": {"max_requests": 64, "max_read_bytes": 1048576, "per_request_ms": 5000},
    }


def test_exact_enrollment_is_finite():
    value = enrollment()
    assert canonical_enrollment(value) == value
    for field, change in [
        ("expires_at_ms", 1_900_001),
        ("runner_profile_id", "other"),
        ("limits", {"max_requests": 65, "max_read_bytes": 1048576, "per_request_ms": 5000}),
    ]:
        changed = copy.deepcopy(value)
        changed[field] = change
        with pytest.raises(FileAccessContractError):
            canonical_enrollment(changed)


@pytest.mark.parametrize(
    "uid,mode,links", [(1000, 0o444, 1), (0, 0o644, 1), (0, 0o444, 2), (0, stat.S_IFLNK | 0o444, 1)]
)
def test_owner_editable_or_linked_enrollment_cannot_self_attest(uid, mode, links):
    flags = mode if mode & stat.S_IFLNK else stat.S_IFREG | mode
    path = SimpleNamespace(
        lstat=lambda: SimpleNamespace(st_uid=uid, st_gid=0, st_mode=flags, st_nlink=links)
    )
    with pytest.raises(FileAccessContractError):
        _root_owned(path, directory=False)


def test_nonlinux_setup_is_refused_before_effects(monkeypatch):
    writes = []
    monkeypatch.setattr(setup.sys, "platform", "win32")
    monkeypatch.setattr(
        runtime.os, "write", lambda descriptor, value: writes.append((descriptor, value))
    )
    monkeypatch.setattr(
        setup.subprocess, "Popen", lambda *_args, **_kwargs: pytest.fail("must not launch")
    )
    with pytest.raises(FileAccessContractError, match="fresh isolated namespace init"):
        setup.enroll_fixed_reader()
    assert writes == [(2, runtime.FILE_ACCESS_LAUNCH_STAGE_MARKERS[1])]
    with pytest.raises(FileAccessContractError):
        setup.assert_probe_identity_unused()


def test_enrollment_entry_is_observed_before_its_dynamic_import(monkeypatch):
    writes = []
    monkeypatch.setattr(
        runtime.os, "write", lambda descriptor, value: writes.append((descriptor, value))
    )
    monkeypatch.setitem(sys.modules, "bluefire.ai_broker_bootstrap", None)

    with pytest.raises(ModuleNotFoundError):
        setup.enroll_fixed_reader()

    assert writes == [(2, runtime.FILE_ACCESS_LAUNCH_STAGE_MARKERS[1])]


def test_enrollment_observation_failure_preserves_the_original_guard(monkeypatch):
    def unavailable(_descriptor, _value):
        raise OSError("diagnostic sink unavailable")

    monkeypatch.setattr(runtime.os, "write", unavailable)
    monkeypatch.setattr(setup.sys, "platform", "win32")

    with pytest.raises(FileAccessContractError, match="fresh isolated namespace init"):
        setup.enroll_fixed_reader()


@pytest.mark.parametrize("enabled", [False, True])
def test_inner_entry_observation_precedes_isolation_facts(monkeypatch, enabled):
    stages = []
    monkeypatch.setattr(
        guest,
        "observe_file_access_launch_stage",
        lambda marker: stages.append(marker),
    )

    def unavailable():
        raise ValueError("isolation facts unavailable")

    monkeypatch.setattr(guest, "isolation_facts", unavailable)

    with pytest.raises(ValueError, match="isolation facts unavailable"):
        guest.inner(8767, file_access=enabled)

    assert stages == ([runtime.FILE_ACCESS_LAUNCH_STAGE_MARKERS[3]] if enabled else [])


@pytest.mark.parametrize("enabled", [False, True])
def test_explicit_start_flag_only(monkeypatch, tmp_path, enabled):
    calls = []
    monkeypatch.setattr(prepared_lab, "start", lambda *args, **kwargs: calls.append((args, kwargs)))
    args = ["start", "--state-dir", str(tmp_path)] + (
        ["--enroll-file-access-probe"] if enabled else []
    )
    prepared_lab.main(args)
    assert calls == [((tmp_path, 8767), {"file_access": enabled})]


@pytest.mark.parametrize("enabled", [False, True])
def test_enrollment_runs_after_isolation_before_owner_drop(monkeypatch, enabled):
    calls = []
    parent = {kind: kind + ":[1]" for kind in guest.KINDS}
    monkeypatch.setattr(guest, "uid", lambda: 0)
    monkeypatch.setattr(guest.os, "getpid", lambda: 1)
    monkeypatch.setattr(guest.socket, "if_nameindex", lambda: [(1, "lo")])
    monkeypatch.setattr(guest, "namespaces", lambda: {kind: kind + ":[2]" for kind in guest.KINDS})
    monkeypatch.setattr(guest, "isolate_mounts", lambda: calls.append("isolate"))
    monkeypatch.setattr(guest.subprocess, "run", lambda *_args, **_kwargs: calls.append("loopback"))
    monkeypatch.setattr(
        guest,
        "observe_file_access_launch_stage",
        lambda marker: calls.append(("stage", marker)),
    )
    monkeypatch.setattr(
        setup,
        "observe_file_access_launch_stage",
        lambda marker: calls.append(("stage", marker)),
    )

    def enroll():
        setup.observe_file_access_launch_stage(runtime.FILE_ACCESS_LAUNCH_STAGE_MARKERS[1])
        calls.append("enroll")

    monkeypatch.setattr(setup, "enroll_fixed_reader", enroll)
    monkeypatch.setattr(guest.os, "execve", lambda *_args: calls.append("drop"))
    guest.enter(8767, json.dumps(parent), file_access=enabled)
    assert calls == [
        *([("stage", runtime.FILE_ACCESS_LAUNCH_STAGE_MARKERS[0])] if enabled else []),
        "isolate",
        "loopback",
        *(
            [
                ("stage", runtime.FILE_ACCESS_LAUNCH_STAGE_MARKERS[1]),
                "enroll",
                ("stage", runtime.FILE_ACCESS_LAUNCH_STAGE_MARKERS[2]),
            ]
            if enabled
            else []
        ),
        "drop",
    ]
