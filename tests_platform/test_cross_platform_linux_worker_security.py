from __future__ import annotations

from pathlib import Path

import pytest

from tools.run_cross_platform_linux_worker import (
    APPROVAL_REVIEWER,
    WorkerError,
    _retained_receiver_key_factory,
    _scan_secrets,
    _scenario_document,
    _secret_encodings,
)


def test_receiver_task_key_factory_retains_every_derived_key() -> None:
    master = b"m" * 32

    def derive(enrollment_key: bytes, task_id: object) -> bytes:
        assert enrollment_key == master
        return str(task_id).encode("ascii").ljust(32, b"-")

    factory, retained = _retained_receiver_key_factory(master, derive)

    first = factory("first")
    second = factory("second")

    assert retained == [first, second]
    assert all(len(key) == 32 for key in retained)


def test_linux_worker_executes_only_the_registered_alternate() -> None:
    root = Path(__file__).resolve().parents[1]

    primary = _scenario_document(root, "primary", 43171)
    alternate = _scenario_document(root, "registered-alternate", 43172)
    primary_step = next(item for item in primary["steps"] if item["id"] == "enumerate_fixture")
    alternate_step = next(item for item in alternate["steps"] if item["id"] == "enumerate_fixture")

    assert primary_step["behavior_id"] == "sandbox.discovery.list.v1"
    assert primary_step["alternates"] == ["sandbox.discovery.metadata.v1"]
    assert alternate_step["behavior_id"] == "sandbox.discovery.metadata.v1"
    assert alternate_step["alternates"] == ["sandbox.discovery.list.v1"]


def test_linux_worker_uses_gate_bound_review_identity() -> None:
    assert APPROVAL_REVIEWER == "gate-11-linux-runtime-reviewer"


@pytest.mark.parametrize("encoding_index", range(7))
def test_linux_run_scan_rejects_every_derived_key_encoding(
    tmp_path: Path, encoding_index: int
) -> None:
    master = b"m" * 32
    derived = b"\xfb\xff" * 16
    encodings = _secret_encodings(derived)
    assert len(encodings) == 7
    (tmp_path / "evidence.bin").write_bytes(b"prefix:" + encodings[encoding_index])

    with pytest.raises(WorkerError, match="secret leaked"):
        _scan_secrets(tmp_path, (master, derived))
