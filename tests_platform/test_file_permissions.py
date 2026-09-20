"""Permission observations are independent facts, not effective-access claims."""

from __future__ import annotations

import os
import stat
import sys
from types import SimpleNamespace

import pytest

from bluefire import file_permissions
from bluefire.collectors import CollectionRequest, FilesystemCollector
from bluefire.evidence import EvidenceError, EvidenceProvenance, SandboxObserver


def observe(observer):
    return observer.observe_file(
        relative_path="data.txt",
        run_id="run-permissions",
        step_id="observe",
        behavior_id="sandbox.discovery.metadata.v1",
        action_id="sandbox.discovery.metadata.v1",
        runner_profile_id="profile.test",
    )


@pytest.mark.parametrize("platform", ["linux", "darwin"])
@pytest.mark.parametrize(
    "mode,group_write,other_write",
    [
        (0o600, False, False),
        (0o640, False, False),
        (0o660, True, False),
        (0o666, True, True),
        (0o602, False, True),
        (0o4640, False, False),
    ],
)
def test_mode_bits_are_not_confused_with_effective_access(
    monkeypatch, platform, mode, group_write, other_write
):
    monkeypatch.setattr(file_permissions.sys, "platform", platform)
    metadata = os.stat_result((stat.S_IFREG | mode, 1, 1, 1, 1, 1, 8, 0, 0, 0))
    fields = file_permissions.observed_permission_fields(metadata)
    assert fields == {
        "permission_status": "available",
        "effective_access": "not_evaluated",
        "permission_mode_octal": f"{mode:04o}",
        "group_write_bit": group_write,
        "other_write_bit": other_write,
        "non_owner_write_bit": group_write or other_write,
    }


@pytest.mark.parametrize(
    "platform,status", [("win32", "unavailable_windows"), ("unsupported", "unsupported_platform")]
)
def test_unavailable_permissions_are_missing_not_false(monkeypatch, platform, status):
    monkeypatch.setattr(file_permissions.sys, "platform", platform)
    assert file_permissions.observed_permission_fields(SimpleNamespace(st_mode=0o777)) == {
        "permission_status": status,
        "effective_access": "not_evaluated",
    }


@pytest.mark.skipif(sys.platform == "win32", reason="Windows ACLs are not POSIX permission bits")
def test_permission_change_is_observed_from_file_without_changing_content(tmp_path):
    path = tmp_path / "data.txt"
    path.write_bytes(b"public test data")
    path.chmod(0o600)
    observer = SandboxObserver(tmp_path)
    baseline = observe(observer)
    path.chmod(0o660)
    changed = observe(observer)
    assert baseline.content["permission_mode_octal"] == "0600"
    assert changed.content["permission_mode_octal"] == "0660"
    assert baseline.content["sha256"] == changed.content["sha256"]
    assert baseline.content["size_bytes"] == changed.content["size_bytes"]
    assert changed.provenance is EvidenceProvenance.OBSERVED
    assert changed.content["effective_access"] == "not_evaluated"
    assert baseline.content_hash != changed.content_hash


def test_mode_change_during_same_handle_read_is_not_stable_evidence(tmp_path, monkeypatch):
    path = tmp_path / "data.txt"
    path.write_bytes(b"public test data")
    observer = SandboxObserver(tmp_path)
    real_fstat = os.fstat
    target = path.stat()
    seen = 0

    def changed_mode(descriptor):
        nonlocal seen
        metadata = real_fstat(descriptor)
        if (metadata.st_dev, metadata.st_ino) == (target.st_dev, target.st_ino):
            seen += 1
            if seen >= 2:
                # Even equal timestamps do not excuse inconsistent mode bits.
                values = {
                    name: getattr(metadata, name)
                    for name in dir(metadata)
                    if name.startswith("st_")
                }
                values["st_mode"] ^= stat.S_IWOTH
                return SimpleNamespace(**values)
        return metadata

    monkeypatch.setattr(os, "fstat", changed_mode)
    with pytest.raises(EvidenceError, match="changed while"):
        observe(observer)


def test_collector_retains_permission_availability_for_detection_and_replay(tmp_path):
    (tmp_path / "data.txt").write_bytes(b"public test data")
    result = FilesystemCollector(tmp_path).collect(
        CollectionRequest(
            run_id="run-permissions",
            step_id="observe",
            behavior_id="sandbox.discovery.metadata.v1",
            action_id="sandbox.discovery.metadata.v1",
            runner_profile_id="profile.test",
            target_scope_ref="runner-profile:profile.test",
            settings={"paths": ["data.txt"]},
        )
    )
    record = result.records[0]
    fields = record.content["observed_fields"]
    assert fields["effective_access"] == "not_evaluated"
    assert fields["permission_status"] == record.content["permission_status"]
    assert fields["sha256"] == record.content["sha256"]
    if sys.platform == "win32":
        assert fields["permission_status"] == "unavailable_windows"
        assert "permission_mode_octal" not in fields
        assert "group_write_bit" not in fields
        assert "other_write_bit" not in fields
        assert "non_owner_write_bit" not in fields
    else:
        assert fields["permission_mode_octal"] == record.content["permission_mode_octal"]
        assert fields["group_write_bit"] == record.content["group_write_bit"]
    assert record.to_dict()["content"]["observed_fields"] == fields
