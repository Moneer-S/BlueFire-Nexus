"""One-use v3 Begin for a durably claimed correction on unchanged v2 setup.

Trusted orchestration supplies current admission and a newly committed Ready
allowance. This boundary never restores baseline authority or stores plaintext.
"""

from __future__ import annotations

import hashlib
import struct
import threading
import time
from typing import Callable

from . import _windows_file_access_setup_native as native_setup
from . import windows_file_access_correction_observation as observation
from . import windows_file_access_enrollment_native as native
from . import windows_file_access_enrollment_setup as setup
from . import windows_file_access_native_wire as wire
from . import windows_file_access_pair_admission as pair
from . import windows_session_facts as session
from .secret_store import WindowsDPAPISecretProvider
from .util import content_hash
from .windows_file_access_pair_credential import _milliseconds, _password_units, _utc, _wipe


class WindowsCorrectionCredentialError(RuntimeError):
    """Path-free refusal, including unknown private-resource cleanup."""


class CorrectionBeginProducer:
    """Consumed even on refusal; historical Ready evidence is never sufficient."""

    def __init__(
        self,
        checked: observation.VerifiedWindowsCorrectionPostimage,
        original: wire.OriginalReservation,
        packet: wire.PreparedPacket,
        *,
        revalidate_original: Callable[[], None],
        require_ready_allowance: Callable[[], None],
        cancellation_event: threading.Event,
    ) -> None:
        from .windows_file_access_correction_admission import correction_host, correction_profile

        try:
            record, _, binding = observation.checked_provenance(checked)
            context = wire._reservation(original, wire._CORRECTION)
            wire._require(type(packet) is wire.PreparedPacket and packet._original == original)
            wire.validate_correction_retained_packet(original, packet._raw)
            request = context["manifest"]["params"]["windows_file_read_request"]
            wire._require(
                request["operation_job_id"] == binding["operation_job_id"]
                and request["generation"] == record["generation"]
                and request["control_revision"] == binding["control_revision"]
                and request["host"] == correction_host(checked._setup)
                and request["resource"] == binding["target_resource"]
                and request["correction_binding_digest"] == content_hash(binding)
                and request["credential_binding_digest"]
                == content_hash(record["credential_reference"])
                and context["profile"] == correction_profile(checked._setup)
            )
            issued = _milliseconds(wire._time(context["manifest"]["requested_at"]))
            expires = _milliseconds(wire._time(context["manifest"]["expires_at"]))
            wire._require(
                record["issued_at_ms"]
                <= binding["issued_at_ms"]
                <= issued
                < expires
                <= binding["expires_at_ms"]
                <= record["expires_at_ms"]
            )
            self._checked, self._original, self._packet = checked, original, packet
            self._record, self._issued, self._binding = record, issued, binding
            self._revalidate, self._allowance = revalidate_original, require_ready_allowance
            self._cancellation = cancellation_event
            self._stopped = threading.Event()
            self._lock = threading.Lock()
            self._consumed = False
            self._cleanup = "not_started"
        except Exception:
            raise WindowsCorrectionCredentialError(
                "Windows correction Begin is unavailable."
            ) from None

    def __repr__(self) -> str:
        return "<WindowsCorrectionBeginProducer one-use>"

    @property
    def credential_cleanup(self) -> str:
        return self._cleanup

    def request_stop(self) -> None:
        self._stopped.set()

    def _current(self) -> None:
        wire._require(not self._stopped.is_set() and not self._cancellation.is_set())
        now = _utc()
        wire._prepared(self._packet, now, time.monotonic())
        wire._require(
            self._binding["issued_at_ms"] <= _milliseconds(now) < self._binding["expires_at_ms"]
        )

    def __call__(self, prefix: bytearray) -> bytearray:
        password = private = None
        backend = None
        provider_started = provider_returned = succeeded = False
        with self._lock:
            if self._consumed:
                raise WindowsCorrectionCredentialError("Windows correction Begin is unavailable.")
            self._consumed = True
        try:
            self._current()
            wire._require(type(prefix) is bytearray)
            wire._require(
                prefix
                == wire.correction_begin_prefix(
                    self._packet, clock=_utc(), monotonic_now=time.monotonic()
                )
            )
            self._revalidate()
            self._allowance()
            self._current()
            self._cleanup = "pending"
            fresh = observation.observe_correction_postimage(
                observation.observation_input(self._checked),
                now_ms=_milliseconds(_utc()),
                deadline=self._packet._deadline,
                cancelled=lambda: self._stopped.is_set() or self._cancellation.is_set(),
            )
            wire._require(
                type(fresh) is observation.VerifiedWindowsCorrectionPostimage
                and fresh._raw == self._checked._raw
                and fresh._receipt == self._checked._receipt
                and fresh._binding == self._checked._binding
                and fresh._descriptor_sha256 == self._checked._descriptor_sha256
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
            wire._require(
                "sha256:" + hashlib.sha256(opaque).hexdigest()
                == self._record["credential_reference"]["protected_sha256"]
            )
            backend.verify_all()
            self._revalidate()
            self._allowance()
            self._current()
            provider = WindowsDPAPISecretProvider()
            wire._require(provider.provider_id == "windows-dpapi-current-user.v1")
            provider_started = True
            plaintext = provider.unprotect(pair._purpose(self._record), opaque)
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
            raise WindowsCorrectionCredentialError(
                "Windows correction Begin is unavailable."
            ) from None
        finally:
            _wipe(password)
            clean = not provider_started or provider_returned
            if backend is not None:
                try:
                    backend.close()
                except Exception:
                    clean = False
            if self._cleanup == "pending":
                clean = clean and backend is not None
                self._cleanup = "verified" if clean else "unknown"
            if not succeeded or not clean:
                _wipe(private)
            if not clean:
                raise WindowsCorrectionCredentialError(
                    "Windows correction Begin cleanup is unknown."
                ) from None
        try:
            self._current()
            self._revalidate()
            self._allowance()
            self._current()
        except Exception:
            _wipe(private)
            raise WindowsCorrectionCredentialError(
                "Windows correction Begin is unavailable."
            ) from None
        assert private is not None
        return private
