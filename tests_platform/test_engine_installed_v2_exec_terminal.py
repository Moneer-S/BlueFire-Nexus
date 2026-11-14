"""Exact source replay for the installed exec attachment terminal contract.

These are constructed contract fixtures, not live Docker or guardian proof.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import bluefire.linux_exec_supervisor_docker as docker_cleanup
from bluefire.engine_exec_operation_supervisor import ExecLifetimeTerminalReceiptV2
from bluefire.engine_installed_v2_exec_terminal import (
    ExecAttachmentTerminalReceiptV2,
    InstalledV2ExecAttachmentError,
    _ExecAttachmentTerminalStore,
)
from bluefire.linux_exec_supervisor_docker import SupervisorDockerCleanupResult
from bluefire.product_store import ProductStore
from bluefire.util import content_hash
from tests_platform.test_linux_exec_supervisor_docker import IDENTITY


def _digest(label: str) -> str:
    return content_hash(label)


def _cleanup_result(label: str) -> SupervisorDockerCleanupResult:
    return SupervisorDockerCleanupResult(
        container_id=IDENTITY.container_id,
        container_identity_digest=IDENTITY.identity_digest,
        daemon_instance_digest=_digest("daemon"),
        request_digests=(_digest(label + " request"),),
        response_digests=(_digest(label + " response"),),
        final_inventory_digest=_digest(label + " inventory"),
        stop_sent=False,
        remove_sent=False,
        test_provider=False,
        live_daemon_proof=True,
        _token=docker_cleanup._RESULT_TOKEN,
    )


def _terminal_sources():
    request_ref = _digest("operation request")
    lease_ref = _digest("operation lease")
    lease_generation = 2
    supervisor = ExecLifetimeTerminalReceiptV2.create(
        request_ref=request_ref,
        lease_ref=lease_ref,
        lease_generation=lease_generation,
        outcome="verified_absent",
        completion_qualification_ref=None,
        final_inventory_digest=_digest("guardian inventory"),
        clock_epoch_ref=_digest("guardian epoch"),
        observed_monotonic_ns=100,
        background_work_absent=True,
        container_absent=True,
    )
    binding = {
        "attempt_id": "engine-attempt-" + "1" * 32,
        "claim_ref": _digest("claim"),
        "controller_fence": _digest("fence"),
        "transaction_ref": _digest("transaction"),
        "owner_ref": _digest("owner"),
        "owner_binding_ref": _digest("binding"),
        "container_id": IDENTITY.container_id,
    }
    values = {
        **{name: binding[name] for name in binding if name != "container_id"},
        "container_identity": IDENTITY,
        "supervisor_activation_ref": _digest("supervisor activation"),
        "docker_custody_journal_ref": _digest("docker custody"),
        "cancellation_audit_tail_ref": None,
        "pending_lease_refs": ((request_ref, lease_ref, lease_generation),),
        "pending_operation_refs": (
            ("operation-" + "2" * 32, request_ref, lease_ref, lease_generation),
        ),
        "supervisor_close_receipts": (supervisor,),
        "source_results": (_cleanup_result("first"), _cleanup_result("second")),
    }
    return binding, values


def test_nonempty_guardian_terminal_retains_and_reopens_exact_source(tmp_path: Path) -> None:
    binding, values = _terminal_sources()
    receipt = ExecAttachmentTerminalReceiptV2.from_sources(**values)
    source = _ExecAttachmentTerminalStore(ProductStore(tmp_path / "product.sqlite"), **binding)
    source.retain(receipt)
    reopened = source.reopen(receipt.receipt_ref)
    assert reopened is not None
    assert reopened.receipt_ref == receipt.receipt_ref
    assert reopened.document == receipt.document()
    assert reopened.document["pending_lease_refs"] == [
        [values["pending_lease_refs"][0][0], values["pending_lease_refs"][0][1], 2]
    ]
    assert reopened.document["supervisor_close_receipts"][0]["receipt_ref"] == (
        values["supervisor_close_receipts"][0].receipt_ref
    )
    assert reopened.document["pending_operation_refs"][0][0] == "operation-" + "2" * 32


def test_unmatched_guardian_close_receipt_cannot_form_terminal() -> None:
    _binding, values = _terminal_sources()
    values["supervisor_close_receipts"] = ()
    with pytest.raises(InstalledV2ExecAttachmentError, match="absence is unverified"):
        ExecAttachmentTerminalReceiptV2.from_sources(**values)
