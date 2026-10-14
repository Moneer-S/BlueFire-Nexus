"""One-use private Begin for an original, durably reserved Windows pair read.

Trusted orchestration supplies the original claim and committed Ready allowance.
This boundary does not create that authority or persist credentials. The existing
DPAPI provider wipes native buffers; immutable Python copies are not erasable.
"""

from __future__ import annotations

import hashlib
import struct
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Callable

from . import _windows_file_access_setup_native as native_setup
from . import windows_file_access_enrollment as enrollment
from . import windows_file_access_enrollment_native as native
from . import windows_file_access_enrollment_setup as setup
from . import windows_file_access_native_wire as wire
from . import windows_file_access_pair_admission as admission
from . import windows_session_facts as session
from .secret_store import WindowsDPAPISecretProvider
from .util import content_hash


class WindowsPairCredentialError(RuntimeError):
    """Path-free refusal, including unknown private-resource cleanup."""


def _utc() -> datetime:
    return datetime.now(timezone.utc)


def _milliseconds(value: datetime) -> int:
    return (value - datetime(1970, 1, 1, tzinfo=timezone.utc)) // timedelta(milliseconds=1)


def _wipe(value: bytearray | None) -> None:
    if value is not None:
        value[:] = b"\0" * len(value)


def _password_units(value: bytearray) -> int:
    wire._require(2 <= len(value) <= 512 and len(value) % 2 == 0)
    high = False
    for (unit,) in struct.iter_unpack("<H", value):
        wire._require(unit != 0)
        if high:
            wire._require(0xDC00 <= unit <= 0xDFFF)
            high = False
        elif 0xD800 <= unit <= 0xDBFF:
            high = True
        else:
            wire._require(not 0xDC00 <= unit <= 0xDFFF)
    wire._require(not high)
    return len(value) // 2


class PairBeginProducer:
    """Private callable consumed even on refusal; never reusable after restart.

    The Ready validator must be captured from an actual committed, one-use Ready
    insertion. A historical Ready query cannot provide that allowance. These
    internal callbacks, like supervisor admission, are trusted orchestration
    premises, not an attestation against arbitrary in-process Python code.
    """

    def __init__(
        self,
        checked: admission.VerifiedWindowsPairSetup,
        original: wire.OriginalReservation,
        packet: wire.PreparedPacket,
        *,
        revalidate_original: Callable[[], None],
        require_ready_allowance: Callable[[], None],
        cancellation_event: threading.Event,
    ) -> None:
        try:
            wire._require(type(checked) is admission.VerifiedWindowsPairSetup)
            record, receipt = admission.checked_provenance(checked)
            context = wire._reservation(original, wire._PAIR)
            wire._require(type(packet) is wire.PreparedPacket and packet._original == original)
            wire.validate_pair_retained_packet(original, packet._raw)
            request = context["manifest"]["params"]["windows_file_read_request"]
            wire._require(
                request["generation"] == record["generation"]
                and request["control_revision"] == 1
                and request["host"] == record["host"]
                and request["resource"] == record["resource"]
                and request["credential_binding_digest"]
                == content_hash(record["credential_reference"])
                and context["profile"] == receipt["private_profile"]
            )
            issued = _milliseconds(wire._time(context["manifest"]["requested_at"]))
            expires = _milliseconds(wire._time(context["manifest"]["expires_at"]))
            wire._require(record["issued_at_ms"] <= issued < expires <= record["expires_at_ms"])
            self._checked, self._original, self._packet = checked, original, packet
            self._record, self._issued = record, issued
            self._revalidate, self._allowance = revalidate_original, require_ready_allowance
            self._cancellation = cancellation_event
            self._stopped = threading.Event()
            self._lock = threading.Lock()
            self._consumed = False
            self._cleanup = "not_started"
        except Exception:
            raise WindowsPairCredentialError("Windows private Begin is unavailable.") from None

    def __repr__(self) -> str:
        return "<WindowsPairBeginProducer one-use>"

    @property
    def credential_cleanup(self) -> str:
        return self._cleanup

    def request_stop(self) -> None:
        self._stopped.set()

    def _current(self) -> None:
        wire._require(not self._stopped.is_set() and not self._cancellation.is_set())
        wire._prepared(self._packet, _utc(), time.monotonic())

    def __call__(self, prefix: bytearray) -> bytearray:
        password = private = None
        backend = None
        provider_started = provider_returned = False
        succeeded = False
        with self._lock:
            if self._consumed:
                raise WindowsPairCredentialError("Windows private Begin is unavailable.")
            self._consumed = True
        try:
            self._current()
            wire._require(type(prefix) is bytearray)
            wire._require(
                prefix
                == wire.pair_begin_prefix(
                    self._packet, clock=_utc(), monotonic_now=time.monotonic()
                )
            )
            self._revalidate()
            self._allowance()
            self._current()
            self._cleanup = "pending"
            fresh = enrollment.read_windows_file_pair_enrollment(
                now_ms=self._issued,
                deadline=self._packet._deadline,
                cancelled=lambda: self._stopped.is_set() or self._cancellation.is_set(),
            )
            wire._require(
                type(fresh) is admission.VerifiedWindowsPairSetup
                and fresh._raw == self._checked._raw
                and fresh._receipt == self._checked._receipt
            )
            self._current()
            owner = session.current_process_principal()
            owner.validate()
            wire._require(
                owner.elevated is False and owner.user_sid == self._record["resource"]["owner_sid"]
            )
            gate = native._Gate(
                self._packet._deadline,
                lambda: self._stopped.is_set() or self._cancellation.is_set(),
            )
            backend = native_setup._NativeSetup(gate, owner, self._issued)
            wire._require(setup._load_pair_receipt(backend) == self._checked._receipt)
            opaque = backend.read_public(setup._CREDENTIAL_PATH, native._MAX_BUFFER)
            reference = self._record["credential_reference"]
            wire._require(
                "sha256:" + hashlib.sha256(opaque).hexdigest() == reference["protected_sha256"]
            )
            backend.verify_all()
            self._revalidate()
            self._allowance()
            self._current()
            provider = WindowsDPAPISecretProvider()
            wire._require(provider.provider_id == "windows-dpapi-current-user.v1")
            provider_started = True
            plaintext = provider.unprotect(admission._purpose(self._record), opaque)
            provider_returned = True
            wire._require(type(plaintext) is bytes)
            password = bytearray(plaintext)
            del plaintext
            units = _password_units(password)
            backend.verify_all()
            wire._require(session.current_process_principal() == owner)
            self._revalidate()
            self._allowance()
            self._current()
            private = bytearray(struct.pack("<I", len(prefix) + 2 + len(password)))
            private.extend(prefix)
            private.extend(struct.pack("<H", units))
            private.extend(password)
            succeeded = True
        except Exception:
            raise WindowsPairCredentialError("Windows private Begin is unavailable.") from None
        finally:
            _wipe(password)
            clean = not provider_started or provider_returned
            if backend is not None:
                try:
                    backend.close()
                except Exception:
                    clean = False
            # A failed concrete observation may have ambiguous native cleanup.
            if self._cleanup == "pending":
                clean = clean and backend is not None
                self._cleanup = "verified" if clean else "unknown"
            if not succeeded or not clean:
                _wipe(private)
            if not clean:
                raise WindowsPairCredentialError(
                    "Windows private Begin cleanup is unknown."
                ) from None
        try:
            self._current()
            self._revalidate()
            self._allowance()
            self._current()
        except Exception:
            _wipe(private)
            raise WindowsPairCredentialError("Windows private Begin is unavailable.") from None
        assert private is not None
        return private
