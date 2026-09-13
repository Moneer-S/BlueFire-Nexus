"""Review failures identify the blocked check without exposing private material."""

from __future__ import annotations

import sqlite3
from typing import Any

import pytest

from bluefire import runner_history_upgrade as upgrade
from bluefire.runner_lifecycle import RunnerLifecycleError
from tests_platform.test_runner_history_upgrade import (
    _HistoryFixture,
    _preserved_bytes,
)
from tests_platform.test_runner_history_upgrade import (
    history as history,
)

_PRIVATE = "C:\\private\\lab\\history.sqlite3 /private/runner/result.json secret=fixture-private"


@pytest.mark.parametrize(
    ("boundary", "message"),
    [
        ("enrollment", "Runner upgrade could not verify the stopped runner and enrollment."),
        ("installed_record", "Runner upgrade could not validate the installed runner record."),
        ("stage", "Runner upgrade could not stage and verify the replacement artifact."),
        ("artifact", "Runner upgrade could not verify the reviewed artifact identities."),
        ("preflight", "Runner upgrade could not audit the execution ledger and its settled state."),
        (
            "ledger_audit",
            "Runner upgrade could not audit the execution ledger and its settled state.",
        ),
        (
            "ledger_read",
            "Runner upgrade could not audit the execution ledger and its settled state.",
        ),
        ("payload", "Runner upgrade could not validate historical execution documents."),
        ("documents", "Runner upgrade could not validate historical execution documents."),
        ("result", "Runner upgrade could not validate historical execution results."),
        ("result_namespace", "Runner upgrade could not verify the durable result files."),
        ("cleanup", "Runner upgrade could not verify pending cleanup or runner activity."),
    ],
)
def test_review_reports_the_failed_stage_and_preserves_private_history(
    history: _HistoryFixture,
    monkeypatch: pytest.MonkeyPatch,
    boundary: str,
    message: str,
) -> None:
    before = _preserved_bytes(history)
    bootstrap = history.lifecycle.bootstrap_record_path.read_bytes()
    calls = []

    def refuse(*args: Any, **kwargs: Any) -> Any:
        calls.append(boundary)
        if boundary in {"preflight", "ledger_audit", "ledger_read"}:
            raise sqlite3.DatabaseError(_PRIVATE)
        if boundary in {"payload", "documents", "result"}:
            raise ValueError(_PRIVATE)
        raise OSError(_PRIVATE)

    lifecycle_calls = {
        "enrollment": "_load_enrollment",
        "installed_record": "_load_bootstrap",
        "stage": "bootstrap_factory",
        "preflight": "_ledger_preflight",
        "cleanup": "_require_no_receipt_obligations",
    }
    module_calls = {
        "artifact": "file_hash",
        "ledger_audit": "audit_runner_ledger",
        "ledger_read": "_pinned_ledger_inspection",
        "documents": "validate_history_documents",
        "result": "validate_stored_execute_result",
    }
    if boundary in lifecycle_calls:
        monkeypatch.setattr(history.lifecycle, lifecycle_calls[boundary], refuse)
    elif boundary in module_calls:
        monkeypatch.setattr(upgrade, module_calls[boundary], refuse)
    elif boundary == "payload":
        monkeypatch.setattr(upgrade.AuthenticatedRunnerServer, "_stored_execute_payload", refuse)
    else:
        read = upgrade._PinnedPrivateDirectory.read_with_snapshot_identity

        def result_read(directory: Any, *args: Any, **kwargs: Any) -> Any:
            if directory.path == history.result_path.parent:
                return refuse()
            return read(directory, *args, **kwargs)

        monkeypatch.setattr(
            upgrade._PinnedPrivateDirectory, "read_with_snapshot_identity", result_read
        )

    with pytest.raises(RunnerLifecycleError) as raised:
        history.review()

    assert calls == [boundary]
    assert str(raised.value) == message
    assert raised.value.__suppress_context__ is True
    assert all(
        private not in str(raised.value)
        for private in ("C:\\private", "/private", "fixture-private")
    )
    assert history.lifecycle.bootstrap_record_path.read_bytes() == bootstrap
    assert _preserved_bytes(history) == before
    assert not (history.lifecycle.control_root / "upgrade-pending.json").exists()


def test_specific_history_refusal_is_not_replaced_by_a_generic_stage(
    history: _HistoryFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    refusal = upgrade.RunnerHistoryUpgradeError("Runner history changed during review.")

    def changed(*args: Any, **kwargs: Any) -> Any:
        raise refusal

    monkeypatch.setattr(upgrade, "validate_history_documents", changed)
    with pytest.raises(RunnerLifecycleError, match="^Runner history changed during review\\.$"):
        history.review()
    assert upgrade.upgrade_failure(refusal) is refusal


def test_unclassified_failure_still_masks_private_details() -> None:
    refused = upgrade.upgrade_failure(OSError(_PRIVATE))
    assert str(refused) == "Runner settled history or upgrade state could not be verified."


def test_review_does_not_convert_interruption_into_a_validation_failure(
    history: _HistoryFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    bootstrap = history.lifecycle.bootstrap_record_path.read_bytes()
    before = _preserved_bytes(history)

    def interrupted(*args: Any, **kwargs: Any) -> Any:
        raise KeyboardInterrupt

    monkeypatch.setattr(upgrade, "validate_history_documents", interrupted)
    with pytest.raises(KeyboardInterrupt):
        history.review()
    assert history.lifecycle.bootstrap_record_path.read_bytes() == bootstrap
    assert _preserved_bytes(history) == before
