from __future__ import annotations

import threading
from dataclasses import replace
from typing import Any, cast

import pytest

from bluefire.strix_worker_endpoint_cleanup import (
    RECEIPT_SCHEMA,
    WorkerEndpointCleanupError,
    WorkerEndpointCleanupObservationV1,
    WorkerEndpointCleanupOwnerV1,
    WorkerEndpointCleanupReceiptV1,
)
from bluefire.util import content_hash


def _digest(character: str) -> str:
    return "sha256:" + character * 64


DIRECTORY = (17, 101)
ENDPOINT = (17, 102)
LAUNCH = (17, 103)


class _Helper:
    helper_ref = _digest("d")
    directory_authority_ref = _digest("e")
    endpoint_authority_ref = _digest("f")

    def __init__(self) -> None:
        self.calls = 0
        self.closed = 0
        self.replacement: dict[str, object] = {}
        self.failure: Exception | None = None
        self.close_failure: Exception | None = None
        self.cleanup_started: threading.Event | None = None
        self.cleanup_release: threading.Event | None = None

    def cleanup(
        self,
        *,
        directory_identity: tuple[int, int],
        endpoint_identity: tuple[int, int],
        launch_identity: tuple[int, int] | None,
    ) -> WorkerEndpointCleanupObservationV1:
        self.calls += 1
        if self.cleanup_started is not None:
            self.cleanup_started.set()
        if self.cleanup_release is not None:
            assert self.cleanup_release.wait(timeout=5)
        if self.failure is not None:
            raise self.failure
        observation = WorkerEndpointCleanupObservationV1(
            helper_ref=self.helper_ref,
            directory_authority_ref=self.directory_authority_ref,
            endpoint_authority_ref=self.endpoint_authority_ref,
            launch_authority_ref=_digest("1") if launch_identity is not None else None,
            directory_identity=directory_identity,
            endpoint_identity=endpoint_identity,
            launch_identity=launch_identity,
            directory_identity_verified=True,
            endpoint_identity_verified=True,
            launch_identity_verified=launch_identity is not None,
            retained_directory_handle=True,
            retained_endpoint_handle=True,
            retained_launch_handle=launch_identity is not None,
            endpoint_entry_matches_retained_handle=True,
            launch_entry_matches_retained_handle=launch_identity is not None,
            fd_relative_cleanup=True,
            symlink_followed=False,
            endpoint_absent=True,
            launch_absent=True,
            directory_absent=True,
        )
        return replace(observation, **cast(Any, self.replacement))

    def launch_authority_ref(self, *, launch_identity: tuple[int, int]) -> str:
        assert launch_identity == LAUNCH
        return _digest("1")

    def close(self) -> None:
        self.closed += 1
        if self.close_failure is not None:
            raise self.close_failure


def _owner(helper: _Helper) -> WorkerEndpointCleanupOwnerV1:
    return WorkerEndpointCleanupOwnerV1(
        attempt_id="engine-attempt-" + "a" * 32,
        claim_digest=_digest("b"),
        worker_containment_ref=_digest("c"),
        directory_identity=DIRECTORY,
        endpoint_identity=ENDPOINT,
        helper=helper,
    )


def test_live_owner_cleans_exact_published_endpoint_once() -> None:
    helper = _Helper()
    owner = _owner(helper)

    receipt = owner.cleanup(launch_identity=LAUNCH)

    assert helper.calls == 1
    assert helper.closed == 1
    assert receipt.document == {
        "schema_version": RECEIPT_SCHEMA,
        "attempt_id": "engine-attempt-" + "a" * 32,
        "claim_digest": _digest("b"),
        "worker_containment_ref": _digest("c"),
        "cleanup_owner_ref": owner.cleanup_owner_ref,
        "helper_ref": _digest("d"),
        "directory_authority_ref": _digest("e"),
        "endpoint_authority_ref": _digest("f"),
        "launch_authority_ref": _digest("1"),
        "directory_identity": list(DIRECTORY),
        "endpoint_identity": list(ENDPOINT),
        "launch_identity": list(LAUNCH),
        "launch_was_published": True,
        "directory_identity_verified": True,
        "endpoint_identity_verified": True,
        "launch_identity_verified": True,
        "retained_directory_handle": True,
        "retained_endpoint_handle": True,
        "retained_launch_handle": True,
        "endpoint_entry_matches_retained_handle": True,
        "launch_entry_matches_retained_handle": True,
        "fd_relative_cleanup": True,
        "symlink_followed": False,
        "endpoint_absent": True,
        "launch_absent": True,
        "directory_absent": True,
        "receipt_ref": receipt.receipt_ref,
    }
    assert owner.cleanup(launch_identity=LAUNCH) is receipt
    assert helper.calls == 1
    assert helper.closed == 1
    with pytest.raises(WorkerEndpointCleanupError, match="another launch identity"):
        owner.cleanup(launch_identity=None)


def test_never_published_launch_is_explicit_and_complete() -> None:
    helper = _Helper()
    receipt = _owner(helper).cleanup(launch_identity=None)

    assert receipt.document["launch_identity"] is None
    assert receipt.document["launch_was_published"] is False
    assert receipt.document["launch_identity_verified"] is False
    assert receipt.document["launch_authority_ref"] is None
    assert receipt.document["retained_launch_handle"] is False
    assert receipt.document["launch_entry_matches_retained_handle"] is False
    assert receipt.document["launch_absent"] is True


@pytest.mark.parametrize(
    ("replacement", "message"),
    [
        ({"helper_ref": _digest("e")}, "identity drifted"),
        ({"directory_authority_ref": _digest("a")}, "identity drifted"),
        ({"endpoint_authority_ref": _digest("a")}, "identity drifted"),
        ({"launch_authority_ref": _digest("a")}, "identity drifted"),
        ({"directory_identity": (17, 201)}, "identity drifted"),
        ({"endpoint_identity": (17, 202)}, "identity drifted"),
        ({"launch_identity": (17, 203)}, "identity drifted"),
        ({"directory_identity_verified": False}, "complete endpoint absence"),
        ({"endpoint_identity_verified": False}, "complete endpoint absence"),
        ({"launch_identity_verified": False}, "identity proof"),
        ({"retained_directory_handle": False}, "complete endpoint absence"),
        ({"retained_endpoint_handle": False}, "complete endpoint absence"),
        ({"retained_launch_handle": False}, "complete endpoint absence"),
        ({"endpoint_entry_matches_retained_handle": False}, "complete endpoint absence"),
        ({"launch_entry_matches_retained_handle": False}, "identity proof"),
        ({"fd_relative_cleanup": False}, "complete endpoint absence"),
        ({"symlink_followed": True}, "identity proof"),
        ({"endpoint_absent": False}, "complete endpoint absence"),
        ({"launch_absent": False}, "complete endpoint absence"),
        ({"directory_absent": False}, "complete endpoint absence"),
    ],
)
def test_live_owner_rejects_identity_drift_or_incomplete_absence(
    replacement: dict[str, object], message: str
) -> None:
    helper = _Helper()
    helper.replacement = replacement
    owner = _owner(helper)

    with pytest.raises(WorkerEndpointCleanupError, match=message):
        owner.cleanup(launch_identity=LAUNCH)
    assert helper.calls == 1
    assert helper.closed == 1
    with pytest.raises(WorkerEndpointCleanupError, match="closed|unavailable"):
        owner.cleanup(launch_identity=LAUNCH)


def test_native_failure_is_terminal_and_releases_live_helper() -> None:
    helper = _Helper()
    helper.failure = OSError("helper lost its directory fd")
    owner = _owner(helper)

    with pytest.raises(WorkerEndpointCleanupError, match="native worker endpoint cleanup failed"):
        owner.cleanup(launch_identity=LAUNCH)
    assert helper.calls == 1
    assert helper.closed == 1
    with pytest.raises(WorkerEndpointCleanupError, match="closed|unavailable"):
        owner.cleanup(launch_identity=LAUNCH)


def test_helper_close_failure_never_exposes_cached_success_receipt() -> None:
    helper = _Helper()
    helper.close_failure = OSError("retained helper descriptor did not close")
    owner = _owner(helper)

    with pytest.raises(WorkerEndpointCleanupError, match="helper could not close"):
        owner.cleanup(launch_identity=LAUNCH)
    assert helper.calls == 1
    assert helper.closed == 1
    with pytest.raises(WorkerEndpointCleanupError, match="closed|unavailable"):
        owner.cleanup(launch_identity=LAUNCH)


def test_cleanup_and_close_are_serialized_around_live_helper() -> None:
    helper = _Helper()
    helper.cleanup_started = threading.Event()
    helper.cleanup_release = threading.Event()
    owner = _owner(helper)
    errors: list[BaseException] = []

    def cleanup() -> None:
        try:
            owner.cleanup(launch_identity=LAUNCH)
        except BaseException as exc:  # pragma: no cover - asserted below
            errors.append(exc)

    cleanup_thread = threading.Thread(target=cleanup)
    cleanup_thread.start()
    assert helper.cleanup_started.wait(timeout=5)
    close_thread = threading.Thread(target=owner.close)
    close_thread.start()
    close_thread.join(timeout=0.1)
    assert close_thread.is_alive()
    assert helper.closed == 0
    helper.cleanup_release.set()
    cleanup_thread.join(timeout=5)
    close_thread.join(timeout=5)

    assert not errors
    assert helper.calls == 1
    assert helper.closed == 1
    assert not cleanup_thread.is_alive()
    assert not close_thread.is_alive()


def test_close_without_cleanup_emits_no_absence_claim() -> None:
    helper = _Helper()
    owner = _owner(helper)
    owner.close()
    owner.close()

    assert helper.calls == 0
    assert helper.closed == 1
    with pytest.raises(WorkerEndpointCleanupError, match="closed"):
        owner.cleanup(launch_identity=None)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("endpoint_identity", [17, 999], "owner reference"),
        ("directory_absent", False, "complete absence"),
        ("endpoint_absent", 1, "booleans"),
        ("launch_was_published", False, "complete absence"),
        ("launch_identity_verified", False, "complete absence"),
        ("retained_endpoint_handle", False, "complete absence"),
        ("retained_launch_handle", False, "complete absence"),
        ("endpoint_entry_matches_retained_handle", False, "complete absence"),
        ("launch_entry_matches_retained_handle", False, "complete absence"),
        ("fd_relative_cleanup", False, "complete absence"),
        ("symlink_followed", True, "complete absence"),
    ],
)
def test_durable_receipt_rejects_tampering(field: str, value: object, message: str) -> None:
    document = _owner(_Helper()).cleanup(launch_identity=LAUNCH).to_dict()
    document[field] = value

    with pytest.raises(WorkerEndpointCleanupError, match=message):
        WorkerEndpointCleanupReceiptV1.from_mapping(document)


def test_serialized_receipt_round_trip_carries_no_live_authority() -> None:
    receipt = _owner(_Helper()).cleanup(launch_identity=LAUNCH)
    reopened = WorkerEndpointCleanupReceiptV1.from_mapping(receipt.to_dict())

    assert reopened.to_dict() == receipt.to_dict()
    assert not hasattr(reopened, "cleanup")


def test_durable_receipt_recomputes_owner_binding_not_only_self_hash() -> None:
    document = _owner(_Helper()).cleanup(launch_identity=LAUNCH).to_dict()
    document["cleanup_owner_ref"] = _digest("f")
    unsigned = {name: item for name, item in document.items() if name != "receipt_ref"}
    document["receipt_ref"] = content_hash(unsigned)

    with pytest.raises(WorkerEndpointCleanupError, match="owner reference"):
        WorkerEndpointCleanupReceiptV1.from_mapping(document)


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("attempt_id", "engine-attempt-short"),
        ("claim_digest", "sha256:not-a-digest"),
        ("worker_containment_ref", "sha256:not-a-digest"),
        ("directory_identity", (-1, 1)),
        ("endpoint_identity", (1, 0)),
    ],
)
def test_owner_refuses_invalid_prebound_identity(name: str, value: object) -> None:
    values: dict[str, object] = {
        "attempt_id": "engine-attempt-" + "a" * 32,
        "claim_digest": _digest("b"),
        "worker_containment_ref": _digest("c"),
        "directory_identity": DIRECTORY,
        "endpoint_identity": ENDPOINT,
        "helper": _Helper(),
    }
    values[name] = value
    with pytest.raises(WorkerEndpointCleanupError):
        WorkerEndpointCleanupOwnerV1(**values)  # type: ignore[arg-type]
