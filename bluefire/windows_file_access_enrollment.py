"""Closed Windows setup candidates, never self-authenticated enrollment.

Parsing and matching declared snapshots prove consistency only. A separate
concrete read-only observer joins protected setup provenance and fresh native
facts. Its result is not task admission, a credential or proof of data access.
"""

from __future__ import annotations

from typing import Any, Callable, cast

from . import _windows_file_access_native_contract as contract
from . import windows_file_access_admission as admission
from . import windows_file_access_pair_admission as pair
from .file_access_contract import FileAccessContractError
from .util import content_hash
from .windows_file_access_admission import (
    ANCHOR_PATH as ANCHOR_PATH,
)
from .windows_file_access_admission import (
    MAX_ENROLLMENT_BYTES as MAX_ENROLLMENT_BYTES,
)
from .windows_file_access_admission import (
    SCHEMA as SCHEMA,
)
from .windows_file_access_admission import (
    VerifiedWindowsSetup as VerifiedWindowsSetup,
)
from .windows_file_access_admission import (
    WindowsEnrollmentCandidate as WindowsEnrollmentCandidate,
)
from .windows_file_access_admission import (
    WindowsEnrollmentUnavailable as WindowsEnrollmentUnavailable,
)
from .windows_file_access_admission import (
    _document as _document,
)
from .windows_file_access_admission import (
    _identity as _identity,
)
from .windows_file_access_admission import (
    _purpose as _purpose,
)
from .windows_file_access_admission import (
    parse_windows_enrollment_candidate as parse_windows_enrollment_candidate,
)
from .windows_session_facts import WindowsPrincipalFacts, WindowsSessionFactsError

_FAILURES = (*admission._FAILURES, WindowsSessionFactsError)


def _match_candidate_observations(
    candidate: WindowsEnrollmentCandidate,
    *,
    anchor_bytes: bytes,
    record_identity: Any,
    owner: WindowsPrincipalFacts,
    observed_bytes: bytes,
) -> None:
    """Private fake-testable consistency only; never returns verified enrollment.

    A future concrete native reader must authenticate protection and provenance
    itself. Supplied observations/anchor mappings cannot make runtime available.
    """
    try:
        contract._require(type(candidate) is WindowsEnrollmentCandidate)
        row = _document(candidate._raw)
        anchor = contract._document(anchor_bytes, 4096)
        contract._exact(
            anchor,
            "schema_version enrollment_id generation host_id record_identity enrollment_digest setup_receipt_digest image_sha256 credential_binding_digest",
        )
        contract._require(anchor["schema_version"] == "bluefire.windows-file-setup-anchor.v1")
        _identity(anchor["record_identity"])
        _identity(record_identity)
        contract._require(anchor["record_identity"] == record_identity)
        for name in (
            "enrollment_digest",
            "setup_receipt_digest",
            "image_sha256",
            "credential_binding_digest",
        ):
            contract._digest(anchor[name])
        contract._require(
            anchor["enrollment_id"] == row["enrollment_id"]
            and anchor["generation"] == row["generation"]
        )
        contract._require(anchor["host_id"] == row["host"]["host_id"])
        contract._require(anchor["enrollment_digest"] == candidate.consistency_digest)
        contract._require(anchor["setup_receipt_digest"] == row["setup_receipt_digest"])
        contract._require(anchor["image_sha256"] == row["native_image"]["sha256"])
        contract._require(
            anchor["credential_binding_digest"] == content_hash(row["credential_reference"])
        )
        contract._require(type(owner) is WindowsPrincipalFacts)
        owner.validate()
        contract._require(
            owner.user_sid == row["resource"]["owner_sid"] and owner.elevated is False
        )
        observed = contract._document(observed_bytes, MAX_ENROLLMENT_BYTES)
        contract._exact(
            observed, "host resource native_image credential_reference account_name account_sid"
        )
        for name in ("host", "resource", "native_image", "credential_reference"):
            contract._require(contract._same(observed[name], row[name]))
        contract._require(observed["account_name"] == candidate.reader_account)
        contract._require(observed["account_sid"] == row["resource"]["reader_sid"])
    except _FAILURES:
        raise FileAccessContractError("Windows setup candidate observations differ.") from None


def read_windows_file_access_enrollment(*, now_ms: int) -> VerifiedWindowsSetup:
    """Observe fixed protected provenance; no caller facts or trust flags accepted."""
    try:
        contract._int(now_ms, 1, 2**63 - 1)
    except _FAILURES:
        raise FileAccessContractError("Windows enrollment time is invalid.") from None
    from ._windows_file_access_enrollment_observe import observe

    try:
        raw, receipt = observe(now_ms=now_ms)
        candidate = parse_windows_enrollment_candidate(raw, now_ms=now_ms)
        contract._require(type(receipt) is bytes)
        contract._require(
            content_hash(contract._document(receipt, 16384))
            == _document(candidate._raw)["setup_receipt_digest"]
        )
        checked = object.__new__(VerifiedWindowsSetup)
        object.__setattr__(checked, "_raw", candidate._raw)
        object.__setattr__(checked, "_receipt", receipt)
        return checked
    except Exception:
        raise WindowsEnrollmentUnavailable("windows_protected_setup_unavailable") from None


def read_windows_file_pair_enrollment(
    *, now_ms: int, deadline: float | None = None, cancelled: Callable[[], bool] | None = None
) -> pair.VerifiedWindowsPairSetup:
    """Observe paired-v2 setup only, without task or credential admission."""
    from ._windows_file_access_enrollment_observe import observe_pair

    return cast(
        pair.VerifiedWindowsPairSetup,
        _read_pair_or_status(
            now_ms,
            lambda **kwargs: observe_pair(**kwargs, deadline=deadline, cancelled=cancelled),
            selected=False,
        ),
    )


def read_windows_file_setup_status(
    *, now_ms: int
) -> VerifiedWindowsSetup | pair.VerifiedWindowsPairSetup:
    """Closed version selection from the actually protected record, never fallback."""
    from ._windows_file_access_enrollment_observe import observe_status

    return _read_pair_or_status(now_ms, observe_status, selected=True)


def _read_pair_or_status(
    now_ms: int, observer: Any, *, selected: bool
) -> VerifiedWindowsSetup | pair.VerifiedWindowsPairSetup:
    try:
        contract._int(now_ms, 1, 2**63 - 1)
        raw, receipt = observer(now_ms=now_ms)
        protocol = admission._protocol_from_record(raw) if selected else admission._PAIR_SETUP
        candidate = (
            parse_windows_enrollment_candidate(raw, now_ms=now_ms)
            if protocol is admission._READER_SETUP
            else pair.parse_windows_pair_enrollment_candidate(raw, now_ms=now_ms)
        )
        contract._require(type(receipt) is bytes)
        contract._require(
            content_hash(contract._document(receipt, 16384))
            == admission._document_for(candidate._raw, protocol)["setup_receipt_digest"]
        )
        kind = (
            VerifiedWindowsSetup
            if protocol is admission._READER_SETUP
            else pair.VerifiedWindowsPairSetup
        )
        checked = object.__new__(kind)
        object.__setattr__(checked, "_raw", candidate._raw)
        object.__setattr__(checked, "_receipt", receipt)
        return cast(VerifiedWindowsSetup | pair.VerifiedWindowsPairSetup, checked)
    except Exception:
        raise WindowsEnrollmentUnavailable("windows_protected_setup_unavailable") from None
