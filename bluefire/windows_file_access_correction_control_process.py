"""One fixed correction child with retained ownership and closure-only recovery."""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from . import _windows_file_access_native_contract as contract
from . import windows_file_access_correction_admission as admission
from . import windows_file_access_correction_child as entry
from . import windows_file_access_pair_admission as pair
from . import windows_file_access_setup_process as shared
from .util import canonical_json_bytes, content_hash
from .windows_file_access_correction_contract import (
    RECEIPT_SCHEMA as RECEIPT_SCHEMA,
)
from .windows_file_access_correction_contract import (
    OwnedCorrectionControlReceipt as OwnedCorrectionControlReceipt,
)
from .windows_file_access_correction_contract import (
    validate_retained_control_receipt as validate_retained_control_receipt,
)


@dataclass(frozen=True)
class CorrectionControlProcessOutcome:
    terminal: dict | None = field(repr=False)
    dispatch: str
    process_cleanup: str
    issue: str | None
    cleanup_owner: CorrectionControlCleanupOwner | None = field(repr=False)
    cleanup_receipt: OwnedCorrectionControlReceipt | None = field(repr=False)
    settled: bool = field(default=False, init=False)


class CorrectionControlCleanupOwner(shared.SetupCleanupOwner):
    """Retain the exact suspended child; retry_cleanup cannot release another effect."""

    INPUT_MAX = entry.INPUT_MAX
    OUTPUT_MAX = entry.OUTPUT_MAX
    REFUSAL_ISSUE = "correction_refused"

    def __init__(
        self,
        checked_setup: pair.VerifiedWindowsPairSetup,
        binding_bytes: bytes,
        *,
        original_monotonic_deadline: float,
        before_dispatch: Callable[[], None],
        cancellation_event: threading.Event,
    ) -> None:
        contract._require(type(binding_bytes) is bytes and callable(before_dispatch))
        record, receipt = pair.checked_provenance(checked_setup)
        self.binding = admission.validate_correction_binding(binding_bytes, checked_setup)
        contract._require(binding_bytes == canonical_json_bytes(self.binding))
        contract._mono(original_monotonic_deadline)
        self.issued = self.binding["issued_at_ms"]
        self.deadline = int(original_monotonic_deadline * 1_000_000_000)
        contract._require(
            0 < self.deadline - time.monotonic_ns() <= admission.OPERATION_MS * 1_000_000
        )
        self.request = canonical_json_bytes(
            {
                "schema_version": entry.REQUEST_SCHEMA,
                "original_record": record,
                "original_receipt": receipt,
                "binding": self.binding,
                "original_deadline_ns": self.deadline,
                "supervision": None,
            }
        )
        contract._require(len(self.request) <= self.INPUT_MAX)
        self._before_dispatch = before_dispatch
        self._dispatch_consumed = self._dispatch_authorized = False
        self._launch_started = False
        self._binding_bytes = binding_bytes
        self._cleanup_receipt: OwnedCorrectionControlReceipt | None = None
        self._initialize_resources(cancellation_event)
        self.current()

    def __repr__(self) -> str:
        return "<WindowsCorrectionControlCleanupOwner retained>"

    def current(self) -> None:
        if self.stopped.is_set() or self.issue is not None:
            raise RuntimeError("Correction stopped")
        if self.cancellation.is_set():
            self.issue = "cancelled"
            raise RuntimeError("Correction cancelled")
        try:
            entry._current(self.binding, self.deadline)
        except Exception:
            self.issue = "deadline"
            raise RuntimeError("Original correction interval ended") from None

    def _entry_spec(self) -> tuple[Path, tuple[str, ...]]:
        return (
            Path(__file__)
            .resolve(strict=True)
            .with_name("windows_file_access_correction_child.py"),
            (),
        )

    def _launch(self) -> None:
        contract._require(not self._launch_started)
        self._launch_started = True
        super()._launch()

    def _before_resume(self) -> None:
        contract._require(not self._dispatch_consumed)
        self._dispatch_consumed = True
        self.current()
        self._before_dispatch()
        self._dispatch_authorized = True

    def _parse_terminal(self, raw: bytes, returncode: int) -> dict:
        return entry.validate_terminal(raw, self.binding, returncode)

    @property
    def cleanup_receipt(self) -> OwnedCorrectionControlReceipt | None:
        return self._cleanup_receipt

    def retry_cleanup(self) -> bool:
        clean = super().retry_cleanup()
        if clean and self._cleanup_receipt is None:
            terminal = self.terminal
            dispatch = (
                "attempted"
                if terminal is not None and terminal["result"] is not None
                else ("unknown" if self.resumed or self._dispatch_authorized else "not_started")
            )
            document = validate_retained_control_receipt(
                {
                    "schema_version": RECEIPT_SCHEMA,
                    "binding_digest": content_hash(self.binding),
                    "dispatch": dispatch,
                    "process_cleanup": "verified",
                    "terminal": terminal,
                    "settled": False,
                },
                self.binding,
            )
            receipt = object.__new__(OwnedCorrectionControlReceipt)
            object.__setattr__(receipt, "_raw", canonical_json_bytes(document))
            object.__setattr__(receipt, "_binding", self._binding_bytes)
            self._cleanup_receipt = receipt
        return clean


def run_correction_control_process(
    checked_setup: pair.VerifiedWindowsPairSetup,
    binding_bytes: bytes,
    *,
    original_monotonic_deadline: float,
    before_dispatch: Callable[[], None],
    cancellation_event: threading.Event,
    retain_cleanup_owner: Callable[[CorrectionControlCleanupOwner], None],
) -> CorrectionControlProcessOutcome:
    """One supervised effect; retained owners can only finish the original closure."""
    if shared.sys.platform != "win32":
        raise RuntimeError("Windows contained correction is unavailable")
    owner = CorrectionControlCleanupOwner(
        checked_setup,
        binding_bytes,
        original_monotonic_deadline=original_monotonic_deadline,
        before_dispatch=before_dispatch,
        cancellation_event=cancellation_event,
    )
    owner.exchange = threading.Thread(
        target=owner._exchange, daemon=True, name="correction-control-exchange"
    )
    try:
        retain_cleanup_owner(owner)
        owner.current()
        owner.exchange.start()
        while not owner.done.is_set():
            owner.current()
            owner.stopped.wait(0.01)
    except BaseException:
        owner.issue = owner.issue or owner.REFUSAL_ISSUE
    finally:
        clean = owner.retry_cleanup()
    receipt = owner.cleanup_receipt
    terminal = None if receipt is None else receipt.document()["terminal"]
    dispatch = receipt.document()["dispatch"] if receipt is not None else "unknown"
    return CorrectionControlProcessOutcome(
        terminal,
        dispatch,
        "verified" if clean else "unknown",
        owner.issue if clean else "cleanup_unknown",
        None if clean else owner,
        receipt,
    )
