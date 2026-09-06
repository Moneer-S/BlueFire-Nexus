from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from bluefire import runner_durable_result as result_module
from bluefire.runner_durable_result import DurableRunnerResult, runner_pending_result_path
from bluefire.runner_private_files import _PinnedPrivateDirectory
from bluefire.runner_transport_errors import (
    RunnerDurableResultExists,
    RunnerPendingResultExists,
    RunnerTransportError,
)


def pending_file(tmp_path: Path):
    owner = DurableRunnerResult()
    final, pending, retained = owner.prepare(tmp_path / "results" / "result.json", "task-01")
    assert retained is None
    payload = b'{"result":"pending"}\n'
    stream = owner.open_pending(pending)
    try:
        stream.write(payload)
        stream.flush()
        identity = stream.identity()
    finally:
        stream.close()
    return owner, final, pending, payload, identity


def test_pending_output_is_published_once_and_reads_are_bounded(tmp_path: Path) -> None:
    owner, final, pending, payload, identity = pending_file(tmp_path)
    committed = b'{"result":"validated"}\n'
    owner.promote(
        pending,
        final,
        pending_expected=payload,
        pending_identity=identity,
        final_payload=committed,
    )
    assert not owner.exists(pending)
    assert owner.read(final, maximum=len(committed)) == committed
    with pytest.raises(RunnerTransportError, match="unavailable"):
        owner.read(final, maximum=len(committed) - 1)
    with pytest.raises(RunnerDurableResultExists):
        owner.prepare(final, "task-01")
    assert final.read_bytes() == committed


@pytest.mark.parametrize("existing", ["pending", "final"])
def test_prepare_preserves_existing_recovery_bytes(tmp_path: Path, existing: str) -> None:
    final = tmp_path / "result.json"
    pending = runner_pending_result_path(final, "task-01")
    occupied = pending if existing == "pending" else final
    occupied.write_bytes(b"preserve this recovery evidence")
    error = RunnerPendingResultExists if existing == "pending" else RunnerDurableResultExists
    with pytest.raises(error):
        DurableRunnerResult().prepare(final, "task-01")
    assert occupied.read_bytes() == b"preserve this recovery evidence"


def test_open_pending_never_truncates_an_existing_file(tmp_path: Path) -> None:
    owner, _final, pending, payload, _identity = pending_file(tmp_path)
    with pytest.raises(RunnerPendingResultExists):
        owner.open_pending(pending)
    assert pending.read_bytes() == payload


@pytest.mark.parametrize("mismatch", ["bytes", "identity"])
def test_promotion_rejects_unverified_pending_output(tmp_path: Path, mismatch: str) -> None:
    owner, final, pending, payload, identity = pending_file(tmp_path)
    with pytest.raises(RunnerTransportError, match="could not be committed"):
        owner.promote(
            pending,
            final,
            pending_expected=b"different bytes" if mismatch == "bytes" else payload,
            pending_identity=(identity[0], identity[1] + 1) if mismatch == "identity" else identity,
            final_payload=b"validated output",
        )
    assert not final.exists()
    assert pending.read_bytes() == payload


def test_racing_final_preserves_both_results_for_reconciliation(tmp_path: Path) -> None:
    owner, final, pending, payload, identity = pending_file(tmp_path)
    final.write_bytes(b"racing final")
    with pytest.raises(RunnerDurableResultExists, match="requires reconciliation"):
        owner.promote(
            pending,
            final,
            pending_expected=payload,
            pending_identity=identity,
            final_payload=b"validated output",
        )
    assert final.read_bytes() == b"racing final"
    assert pending.read_bytes() == payload


@pytest.mark.parametrize("failure", ["unlink", "close"])
def test_failure_after_publication_requires_reconciliation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    owner, final, pending, payload, identity = pending_file(tmp_path)
    real_close = _PinnedPrivateDirectory.close

    def fail_unlink(*_args, **_kwargs):
        raise OSError("injected pending removal failure")

    def fail_close(guard):
        real_close(guard)
        raise OSError("injected parent close failure")

    monkeypatch.setattr(
        _PinnedPrivateDirectory, failure, fail_unlink if failure == "unlink" else fail_close
    )
    with pytest.raises(RunnerDurableResultExists, match="may be committed"):
        owner.promote(
            pending,
            final,
            pending_expected=payload,
            pending_identity=identity,
            final_payload=b"validated output",
        )
    assert final.read_bytes() == b"validated output"
    assert pending.exists() is (failure == "unlink")


@pytest.mark.parametrize("identity_kind", ["missing", "foreign", "owned"])
def test_pending_cleanup_requires_the_owned_identity(tmp_path: Path, identity_kind: str) -> None:
    owner, _final, pending, payload, identity = pending_file(tmp_path)
    expected = {"missing": None, "foreign": (identity[0], identity[1] + 1), "owned": identity}
    owner.remove_pending(pending, expected_identity=expected[identity_kind])
    if identity_kind == "owned":
        assert not pending.exists()
    else:
        assert pending.read_bytes() == payload


@pytest.mark.parametrize("invalid", ["path", "delete", "share_delete"])
def test_borrowed_parent_must_offer_the_exact_exclusive_handoff(
    tmp_path: Path, invalid: str
) -> None:
    live = SimpleNamespace(
        path=tmp_path / "other" if invalid == "path" else tmp_path,
        delete=invalid == "delete",
        share_delete=invalid == "share_delete",
    )
    owner = DurableRunnerResult(parent_guard=live)  # type: ignore[arg-type]
    with pytest.raises(RunnerTransportError, match="exclusive watchdog handoff"):
        owner._parent_guard(tmp_path)


def test_fresh_parent_guard_retains_borrowed_directory_and_mount_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    live = SimpleNamespace(
        path=tmp_path,
        delete=False,
        share_delete=False,
        directory_identity=lambda: (7, 9),
        directory_mount_identity=lambda: "mount-identity",
    )
    captured = []
    sentinel = object()

    def pin(path, **options):
        captured.append((path, options))
        return sentinel

    monkeypatch.setattr(result_module, "_PinnedPrivateDirectory", pin)
    owner = DurableRunnerResult(parent_guard=live)  # type: ignore[arg-type]
    assert owner._parent_guard(tmp_path) is sentinel
    assert captured == [
        (tmp_path, {"expected_identity": (7, 9), "expected_mount_identity": "mount-identity"})
    ]
