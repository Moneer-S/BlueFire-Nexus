"""Concrete correction postimage facts, not renewed setup or task authority."""

from __future__ import annotations

import time
from typing import Callable

from . import _windows_file_access_enrollment_observe as native_observation
from . import windows_file_access_pair_admission as pair
from ._windows_file_access_native_contract import _digest, _int, _require
from .windows_file_access_correction_contract import (
    CorrectionObservationInput as CorrectionObservationInput,
)
from .windows_file_access_correction_contract import (
    VerifiedWindowsCorrectionPostimage as VerifiedWindowsCorrectionPostimage,
)
from .windows_file_access_correction_contract import (
    _validated as _validated,
)
from .windows_file_access_correction_contract import (
    checked_provenance as checked_provenance,
)
from .windows_file_access_correction_contract import (
    observation_input as observation_input,
)


class WindowsCorrectionObservationError(RuntimeError):
    """Path-free refusal, including uncertain concrete observation cleanup."""


def observe_correction_preimage(
    checked: pair.VerifiedWindowsPairSetup,
    *,
    now_ms: int,
    deadline: float,
    cancelled: Callable[[], bool],
) -> str:
    """Read the exact current readable descriptor; never open data or WRITE_DAC."""
    try:
        record, _ = pair.checked_provenance(checked)
        _int(now_ms, 1, 2**63 - 1)
        _require(record["issued_at_ms"] <= now_ms < record["expires_at_ms"])
        raw, receipt, descriptor = native_observation.observe_correction_preimage(
            now_ms=now_ms, deadline=deadline, cancelled=cancelled
        )
        _require(raw == checked._raw and receipt == checked._receipt)
        _digest(descriptor)
        return descriptor
    except Exception:
        raise WindowsCorrectionObservationError(
            "Windows correction preimage is unavailable."
        ) from None


def observe_correction_postimage(
    value: CorrectionObservationInput,
    *,
    now_ms: int,
    deadline: float,
    cancelled: Callable[[], bool],
) -> VerifiedWindowsCorrectionPostimage:
    """Mint only after unchanged v2 provenance and the exact postimage are observed.

    Trusted orchestration supplies the durable claim and verified setter digest;
    this observer does not attribute the effect or establish a Ready allowance.
    Original setup/account expiries and the supplied hard deadline never renew.
    """
    try:
        record, _, binding = _validated(value)
        _int(now_ms, 1, 2**63 - 1)
        _require(binding["issued_at_ms"] <= now_ms < binding["expires_at_ms"])
        raw, receipt = native_observation.observe_correction(
            now_ms=now_ms,
            original_raw=value.checked_setup._raw,
            original_receipt=value.checked_setup._receipt,
            target_resource=binding["target_resource"],
            descriptor_sha256=value.target_descriptor_sha256,
            deadline=deadline,
            cancelled=cancelled,
        )
        _require(raw == value.checked_setup._raw and receipt == value.checked_setup._receipt)
        _require(
            now_ms
            <= time.time_ns() // 1_000_000
            < binding["expires_at_ms"]
            <= record["expires_at_ms"]
        )
        checked = object.__new__(VerifiedWindowsCorrectionPostimage)
        for name, item in (
            ("_raw", raw),
            ("_receipt", receipt),
            ("_binding", value.binding_bytes),
            ("_descriptor_sha256", value.target_descriptor_sha256),
            ("_setup", value.checked_setup),
        ):
            object.__setattr__(checked, name, item)
        checked_provenance(checked)
        return checked
    except Exception:
        raise WindowsCorrectionObservationError(
            "Windows correction postimage is unavailable."
        ) from None
