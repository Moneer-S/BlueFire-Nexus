from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path

import pytest

import bluefire.evidence as evidence_module
from bluefire.evidence import (
    EvidenceError,
    EvidenceGraph,
    EvidenceProvenance,
    EvidenceRecord,
    SandboxObserver,
)


def _record(**overrides):
    values = {
        "run_id": "run-test",
        "step_id": "deliver",
        "behavior_id": "fixture.deliver.v1",
        "action_id": "sandbox.fixture.create.v1",
        "provenance": EvidenceProvenance.EXECUTED,
        "producer": "runner.test",
        "runner_profile_id": "profile.test",
        "content": {"artifact_type": "file", "path": "fixture/input.txt"},
        "target_scope_ref": "runner-profile:profile.test",
        "timestamp": "2026-01-01T00:00:00Z",
    }
    values.update(overrides)
    return EvidenceRecord.create(**values)


def test_provenance_is_explicit_and_hashes_are_stable() -> None:
    first = _record()
    second = _record()
    assert first == second
    assert first.to_dict()["provenance"] == "executed"
    assert first.content_hash.startswith("sha256:")
    assert first.record_hash.startswith("sha256:")


def test_evidence_rehydration_verifies_content_record_and_identity_hashes() -> None:
    record = _record()
    assert EvidenceRecord.from_mapping(record.to_dict()) == record

    tampered = record.to_dict()
    tampered["content"] = {"artifact_type": "file", "path": "staged/tampered.txt"}
    with pytest.raises(EvidenceError, match="content hash"):
        EvidenceRecord.from_mapping(tampered)


def test_evidence_graph_rejects_dangling_parent() -> None:
    graph = EvidenceGraph()
    child = _record(parent_evidence_ids=("missing",))
    with pytest.raises(EvidenceError, match="unknown parents"):
        graph.add(child)


def test_evidence_graph_rejects_parent_from_another_run() -> None:
    graph = EvidenceGraph()
    parent = _record(run_id="run-first")
    graph.add(parent)

    with pytest.raises(EvidenceError, match="another run"):
        graph.add(_record(run_id="run-second", parent_evidence_ids=(parent.evidence_id,)))


def test_sandbox_observer_records_independent_file_state(tmp_path: Path) -> None:
    root = tmp_path / "sandbox"
    path = root / "staged" / "artifact.txt"
    path.parent.mkdir(parents=True)
    path.write_text("benign fixture", encoding="utf-8")
    parent = _record()

    observed = SandboxObserver(root).observe_file(
        relative_path="staged/artifact.txt",
        run_id="run-test",
        step_id="stage",
        behavior_id="collection.stage_fixture.v1",
        action_id="sandbox.collection.stage.v1",
        runner_profile_id="profile.test",
        parent_evidence_ids=(parent.evidence_id,),
    )

    assert observed.provenance is EvidenceProvenance.OBSERVED
    assert observed.content["size_bytes"] == len("benign fixture")
    assert observed.content["sha256"]


def test_sandbox_observer_refuses_escape(tmp_path: Path) -> None:
    root = tmp_path / "sandbox"
    root.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("private", encoding="utf-8")
    observer = SandboxObserver(root)

    with pytest.raises(EvidenceError):
        observer.observe_file(
            relative_path="../outside.txt",
            run_id="run-test",
            step_id="stage",
            behavior_id="collection.stage_fixture.v1",
            action_id="sandbox.collection.stage.v1",
            runner_profile_id="profile.test",
        )


def test_sandbox_observer_refuses_link_escape(tmp_path: Path) -> None:
    root = tmp_path / "sandbox"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "private.txt").write_text("private", encoding="utf-8")
    linked = root / "linked"
    try:
        linked.symlink_to(outside, target_is_directory=True)
    except (NotImplementedError, OSError):
        pytest.skip("directory links are unavailable on this host")

    with pytest.raises(EvidenceError):
        SandboxObserver(root).observe_file(
            relative_path="linked/private.txt",
            run_id="run-test",
            step_id="stage",
            behavior_id="collection.stage_fixture.v1",
            action_id="sandbox.collection.stage.v1",
            runner_profile_id="profile.test",
        )


def test_sandbox_observer_refuses_link_as_authorized_root(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "private.txt").write_text("private", encoding="utf-8")
    linked_root = tmp_path / "sandbox"
    try:
        linked_root.symlink_to(outside, target_is_directory=True)
    except (NotImplementedError, OSError):
        pytest.skip("directory links are unavailable on this host")

    with pytest.raises(EvidenceError, match="links or junctions|unavailable or unsafe"):
        SandboxObserver(linked_root)


@pytest.mark.skipif(os.name != "nt", reason="Windows root-junction regression")
def test_sandbox_observer_refuses_junction_as_authorized_root(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "private.txt").write_text("private", encoding="utf-8")
    linked_root = tmp_path / "sandbox"
    created = subprocess.run(
        ["cmd.exe", "/d", "/c", "mklink", "/J", str(linked_root), str(outside)],
        check=False,
        capture_output=True,
        timeout=10,
    )
    if created.returncode != 0:
        pytest.skip("directory junctions are unavailable on this host")
    try:
        with pytest.raises(EvidenceError, match="links or junctions|unavailable or unsafe"):
            SandboxObserver(linked_root)
    finally:
        linked_root.rmdir()


@pytest.mark.skipif(os.name != "nt", reason="Windows parent-junction race regression")
def test_sandbox_observer_refuses_parent_junction_swap_while_pinning_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parent = tmp_path / "parent"
    root = parent / "sandbox"
    root.mkdir(parents=True)
    (root / "artifact.txt").write_text("expected", encoding="utf-8")
    outside_parent = tmp_path / "outside-parent"
    outside_root = outside_parent / "sandbox"
    outside_root.mkdir(parents=True)
    (outside_root / "artifact.txt").write_text("private", encoding="utf-8")
    held_parent = tmp_path / "parent-original"
    real_open = evidence_module._windows_open_directory_handle
    swapped = False

    def swapping_open(path: Path) -> int:
        nonlocal swapped
        if not swapped:
            parent.rename(held_parent)
            created = subprocess.run(
                ["cmd.exe", "/d", "/c", "mklink", "/J", str(parent), str(outside_parent)],
                check=False,
                capture_output=True,
                timeout=10,
            )
            if created.returncode != 0:
                held_parent.rename(parent)
                pytest.skip("directory junctions are unavailable on this host")
            swapped = True
        return real_open(path)

    monkeypatch.setattr(evidence_module, "_windows_open_directory_handle", swapping_open)
    try:
        with pytest.raises(EvidenceError, match="links or junctions|changed while it was pinned"):
            SandboxObserver(root)
    finally:
        if swapped:
            parent.rmdir()
            held_parent.rename(parent)


@pytest.mark.skipif(os.name == "nt", reason="POSIX parent-link race regression")
def test_sandbox_observer_refuses_parent_link_swap_while_pinning_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parent = tmp_path / "parent"
    root = parent / "sandbox"
    root.mkdir(parents=True)
    (root / "artifact.txt").write_text("expected", encoding="utf-8")
    outside_parent = tmp_path / "outside-parent"
    outside_root = outside_parent / "sandbox"
    outside_root.mkdir(parents=True)
    (outside_root / "artifact.txt").write_text("private", encoding="utf-8")
    held_parent = tmp_path / "parent-original"
    real_open_root = SandboxObserver._open_posix_root
    swapped = False

    def swapping_open_root(observer: SandboxObserver) -> int:
        nonlocal swapped
        if not swapped:
            parent.rename(held_parent)
            try:
                parent.symlink_to(outside_parent, target_is_directory=True)
            except (NotImplementedError, OSError):
                held_parent.rename(parent)
                pytest.skip("directory links are unavailable on this host")
            swapped = True
        return real_open_root(observer)

    monkeypatch.setattr(SandboxObserver, "_open_posix_root", swapping_open_root)
    try:
        with pytest.raises(EvidenceError, match="unavailable or unsafe"):
            SandboxObserver(root)
    finally:
        if swapped:
            parent.unlink()
            held_parent.rename(parent)


@pytest.mark.skipif(os.name == "nt", reason="POSIX root-identity race regression")
def test_sandbox_observer_refuses_plain_parent_replacement_after_initial_pin(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parent = tmp_path / "parent"
    root = parent / "sandbox"
    root.mkdir(parents=True)
    (root / "artifact.txt").write_text("expected", encoding="utf-8")
    replacement_parent = tmp_path / "replacement-parent"
    replacement_root = replacement_parent / "sandbox"
    replacement_root.mkdir(parents=True)
    (replacement_root / "artifact.txt").write_text("private", encoding="utf-8")
    held_parent = tmp_path / "parent-original"
    displaced_parent = tmp_path / "parent-rejected"
    path_type = type(root)
    real_resolve = path_type.resolve
    swapped = False

    def swapping_resolve(path: Path, strict: bool = False) -> Path:
        nonlocal swapped
        if not swapped and path == root.absolute():
            parent.rename(held_parent)
            replacement_parent.rename(parent)
            swapped = True
        return real_resolve(path, strict=strict)

    monkeypatch.setattr(path_type, "resolve", swapping_resolve)
    try:
        with pytest.raises(EvidenceError, match="changed while it was pinned"):
            SandboxObserver(root)
    finally:
        if swapped:
            parent.rename(displaced_parent)
            held_parent.rename(parent)


def test_sandbox_observer_pins_exact_root_identity(tmp_path: Path) -> None:
    root = tmp_path / "sandbox"
    root.mkdir()
    (root / "artifact.txt").write_text("expected", encoding="utf-8")
    replacement = tmp_path / "replacement"
    replacement.mkdir()
    (replacement / "artifact.txt").write_text("replacement", encoding="utf-8")
    original = tmp_path / "sandbox-original"
    observer = SandboxObserver(root)

    root.rename(original)
    replacement.rename(root)
    with pytest.raises(EvidenceError, match="root identity changed"):
        observer.observe_file(
            relative_path="artifact.txt",
            run_id="run-test",
            step_id="stage",
            behavior_id="collection.stage_fixture.v1",
            action_id="sandbox.collection.stage.v1",
            runner_profile_id="profile.test",
        )


@pytest.mark.skipif(os.name != "nt", reason="Windows path normalization regression")
@pytest.mark.parametrize(
    "relative_path",
    ["D:/outside.txt", "artifact.txt:stream", "CON", "nested/NUL.txt", "trailing./x"],
)
def test_sandbox_observer_refuses_non_file_windows_path_forms(
    tmp_path: Path,
    relative_path: str,
) -> None:
    root = tmp_path / "sandbox"
    root.mkdir()
    observer = SandboxObserver(root)

    with pytest.raises(EvidenceError, match="ordinary Windows files"):
        observer.observe_file(
            relative_path=relative_path,
            run_id="run-test",
            step_id="stage",
            behavior_id="collection.stage_fixture.v1",
            action_id="sandbox.collection.stage.v1",
            runner_profile_id="profile.test",
        )


@pytest.mark.skipif(os.name != "nt", reason="Windows junction containment regression")
def test_sandbox_observer_refuses_junction_escape(tmp_path: Path) -> None:
    root = tmp_path / "sandbox"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "private.txt").write_text("private", encoding="utf-8")
    junction = root / "junction"
    created = subprocess.run(
        ["cmd.exe", "/d", "/c", "mklink", "/J", str(junction), str(outside)],
        check=False,
        capture_output=True,
        timeout=10,
    )
    if created.returncode != 0:
        pytest.skip("directory junctions are unavailable on this host")
    try:
        with pytest.raises(EvidenceError):
            SandboxObserver(root).observe_file(
                relative_path="junction/private.txt",
                run_id="run-test",
                step_id="stage",
                behavior_id="collection.stage_fixture.v1",
                action_id="sandbox.collection.stage.v1",
                runner_profile_id="profile.test",
            )
    finally:
        junction.rmdir()


@pytest.mark.skipif(os.name == "nt", reason="POSIX directory-descriptor regression")
def test_sandbox_observer_rejects_path_swap_after_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "sandbox"
    root.mkdir()
    observed_path = root / "artifact.txt"
    observed_path.write_text("expected", encoding="utf-8")
    outside = tmp_path / "outside.txt"
    outside.write_text("private", encoding="utf-8")
    held_path = root / "artifact-opened.txt"
    real_fstat = evidence_module.os.fstat
    regular_descriptors: list[int] = []
    swapped = False

    def swapping_fstat(descriptor: int):
        nonlocal swapped
        details = real_fstat(descriptor)
        if stat.S_ISREG(details.st_mode):
            regular_descriptors.append(descriptor)
            if not swapped:
                observed_path.rename(held_path)
                os.utime(
                    held_path,
                    ns=(details.st_atime_ns, details.st_mtime_ns + 1_000_000_000),
                )
                observed_path.symlink_to(outside)
                swapped = True
        return details

    monkeypatch.setattr(evidence_module.os, "fstat", swapping_fstat)

    with pytest.raises(EvidenceError, match="changed while"):
        SandboxObserver(root).observe_file(
            relative_path="artifact.txt",
            run_id="run-test",
            step_id="stage",
            behavior_id="collection.stage_fixture.v1",
            action_id="sandbox.collection.stage.v1",
            runner_profile_id="profile.test",
        )

    assert swapped is True
    assert len(regular_descriptors) == 2
    assert regular_descriptors[0] == regular_descriptors[1]


@pytest.mark.skipif(os.name == "nt", reason="POSIX root-descriptor regression")
def test_sandbox_observer_rejects_root_swap_during_observation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "sandbox"
    root.mkdir()
    (root / "artifact.txt").write_text("expected", encoding="utf-8")
    replacement = tmp_path / "replacement"
    replacement.mkdir()
    (replacement / "artifact.txt").write_text("replacement", encoding="utf-8")
    original = tmp_path / "sandbox-original"
    observer = SandboxObserver(root)
    real_fstat = evidence_module.os.fstat
    swapped = False

    def swapping_fstat(descriptor: int):
        nonlocal swapped
        details = real_fstat(descriptor)
        if stat.S_ISREG(details.st_mode) and not swapped:
            root.rename(original)
            replacement.rename(root)
            swapped = True
        return details

    monkeypatch.setattr(evidence_module.os, "fstat", swapping_fstat)

    with pytest.raises(EvidenceError, match="root identity changed"):
        observer.observe_file(
            relative_path="artifact.txt",
            run_id="run-test",
            step_id="stage",
            behavior_id="collection.stage_fixture.v1",
            action_id="sandbox.collection.stage.v1",
            runner_profile_id="profile.test",
        )

    assert swapped is True


@pytest.mark.skipif(os.name != "nt", reason="Windows root-handle regression")
def test_sandbox_observer_blocks_root_swap_during_observation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "sandbox"
    root.mkdir()
    (root / "artifact.txt").write_text("expected", encoding="utf-8")
    original = tmp_path / "sandbox-original"
    observer = SandboxObserver(root)
    real_fstat = evidence_module.os.fstat
    attempted = False
    denied = False

    def swapping_fstat(descriptor: int):
        nonlocal attempted, denied
        details = real_fstat(descriptor)
        if stat.S_ISREG(details.st_mode) and not attempted:
            attempted = True
            try:
                root.rename(original)
            except OSError:
                denied = True
        return details

    monkeypatch.setattr(evidence_module.os, "fstat", swapping_fstat)

    observed = observer.observe_file(
        relative_path="artifact.txt",
        run_id="run-test",
        step_id="stage",
        behavior_id="collection.stage_fixture.v1",
        action_id="sandbox.collection.stage.v1",
        runner_profile_id="profile.test",
    )

    assert attempted is True
    assert denied is True
    assert observed.content["size_bytes"] == len("expected")


def test_sandbox_observer_enforces_file_size_bound(tmp_path: Path) -> None:
    root = tmp_path / "sandbox"
    root.mkdir()
    (root / "large.bin").write_bytes(b"12345")
    observer = SandboxObserver(root, max_file_bytes=4)

    with pytest.raises(EvidenceError, match="byte limit"):
        observer.observe_file(
            relative_path="large.bin",
            run_id="run-test",
            step_id="collect",
            behavior_id="collection.stage_fixture.v1",
            action_id="sandbox.collection.stage.v1",
            runner_profile_id="profile.test",
        )
