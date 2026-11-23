"""Dedicated AD hooks on the existing authenticated receiver and durable ledger.

The inherited public transport remains control-only: this source is not an
execution toggle. Actual host admission must join the pinned native Ready path
before production construction exposes execute. No alternate task scheduler,
credential recovery, listener startup, or discovery is performed here.
"""

from __future__ import annotations

import secrets
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from .ad_smb_channel_transport import EnrolledAdSmbServer
from .ad_smb_contract import AdSmbError, AdSmbScope
from .ad_smb_credentials import CredentialBinding
from .ad_smb_native_results import project_native_read
from .ad_smb_receiver_results import context, native_generation, result_record, stored_result
from .ad_smb_worker_process import run_worker
from .ad_smb_worker_wire import WorkerPacket, prepare_packet
from .runner_transport import AuthenticatedRunnerServer, _RequestRefusal
from .runner_transport_errors import RunnerTransportError
from .runner_trust import RunnerEnrollment
from .util import canonical_json_bytes

_READS = [(phase, index) for phase in ("baseline", "retest") for index in range(3)]
_MEMBER = {("inspect", 0), ("harden", 0), ("rollback", 0), ("audit", 0)}


def _now() -> datetime:
    return datetime.now(timezone.utc)


class AdSmbReceiver(EnrolledAdSmbServer):
    """Private fixed-worker integration; inherited execution admission stays closed."""

    _ad_credentials: CredentialBinding | None = None

    def _context(self, manifest: Mapping[str, Any], profile: Mapping[str, Any]) -> dict[str, Any]:
        value = context(manifest, profile)
        request = value["manifest"]["params"]["ad_smb_request"]
        if (
            request["host"]["native_generation"] != native_generation(self.channel)
            or profile["runner_id"] != self.channel.to_dict()["runner_id"]
        ):
            raise AdSmbError("AD native implementation generation differs from enrollment.")
        # This validates scope/role/limits before a ledger reservation without
        # decrypting anything. The real reader UPN hash is selected before Ready.
        reading = self.channel.to_dict()["role"] == "client"
        prepare_packet(
            value,
            self.channel,
            challenge="0" * 64,
            credential_binding_digest=request["principal_binding_digest"] if reading else None,
            expected_upn_sha256="sha256:" + "0" * 64 if reading else None,
            prior_local_authentication_ids=[],
            clock=_now(),
        )
        return value

    def _original_rows(self, connection: sqlite3.Connection) -> list[dict[str, Any]]:
        rows = connection.execute(
            "SELECT * FROM transport_tasks WHERE operation = 'execute' LIMIT 11"
        ).fetchall()
        if len(rows) > 10:
            raise _RequestRefusal("ledger_capacity")
        return [dict(row) for row in rows]

    def _row_context(self, row: Mapping[str, Any]) -> dict[str, Any]:
        manifest, profile, grant, managed_descriptor = self._stored_execute_payload(row)
        if grant is not None or managed_descriptor is not None:
            raise AdSmbError("AD cannot use another protected execution protocol.")
        value = context(manifest, profile)
        if (
            value["task_id"] != row["task_id"]
            or value["transport_request_hash"] != row["request_hash"]
            or profile["profile_id"] != self.channel.to_dict()["profile_id"]
        ):
            raise AdSmbError("AD ledger original identity changed.")
        return value

    def _validate_execute_reservation(
        self, connection: sqlite3.Connection, request: Mapping[str, Any]
    ) -> None:
        try:
            supplied = self._require_payload(request, frozenset({"manifest", "profile"}))
            current = self._context(supplied["manifest"], supplied["profile"])
            step = current["manifest"]["params"]["ad_smb_request"]
            if (
                current["task_id"] != request["task_id"]
                or current["transport_request_hash"] != request["request_hash"]
            ):
                raise AdSmbError("AD task identity differs from reservation.")
            prior = [
                self._row_context(row)["manifest"]["params"]["ad_smb_request"]
                for row in self._original_rows(connection)
            ]
            if any(
                old["scope_digest"] != step["scope_digest"]
                or old["workflow_job_id"] != step["workflow_job_id"]
                or old["host"] != step["host"]
                or old["environment_digest"] != step["environment_digest"]
                or old["principal_binding_digest"] != step["principal_binding_digest"]
                for old in prior
            ):
                raise AdSmbError("AD receiver already owns another original scope or workflow.")
            slots = [(old["phase"], old["index"]) for old in prior]
            slot = (step["phase"], step["index"])
            if len(set(slots)) != len(slots) or slot in slots:
                raise AdSmbError("AD phase slot has already been reserved.")
            limits = AdSmbScope.from_mapping(step["scope"]).to_dict()["limits"]
            if self.channel.to_dict()["role"] == "client":
                if (
                    set(slots) != set(_READS[: len(slots)])
                    or len(slots) >= min(6, limits["sessions"], limits["business_attempts"])
                    or slot != _READS[len(slots)]
                ):
                    raise AdSmbError("AD finite read reservation is exhausted or out of order.")
            elif (
                slot not in _MEMBER
                or any(old not in _MEMBER for old in slots)
                or (slot != ("inspect", 0) and ("inspect", 0) not in slots)
                or (slot == ("rollback", 0) and ("harden", 0) not in slots)
            ):
                raise AdSmbError("AD member reservation is outside the finite recipe.")
        except (AdSmbError, KeyError, TypeError, ValueError, RunnerTransportError):
            raise _RequestRefusal("request_invalid") from None

    def _validated_execute_result(
        self, result: Mapping[str, Any], manifest: Mapping[str, Any], profile: Mapping[str, Any]
    ) -> dict[str, Any]:
        try:
            return stored_result(
                result, manifest, profile, self.channel, maximum=self.max_frame_bytes - 4096
            )
        except AdSmbError:
            raise RunnerTransportError("AD original terminal is unavailable or invalid.") from None

    def _prior_luids(self, task_id: str) -> list[str]:
        if self.channel.to_dict()["role"] != "client":
            return []
        with self._database() as connection:
            rows = self._original_rows(connection)
        by_slot = {}
        current_slot = None
        for row in rows:
            original = self._row_context(row)
            step = original["manifest"]["params"]["ad_smb_request"]
            slot = (step["phase"], step["index"])
            if slot not in _READS or slot in by_slot:
                raise AdSmbError("AD read ledger has invalid or duplicate recipe slots.")
            by_slot[slot] = (row, original)
            if row["task_id"] == task_id:
                current_slot = slot
        if current_slot is None:
            raise AdSmbError("AD read has no original reservation.")
        ids: list[str] = []
        for slot in _READS[: _READS.index(current_slot)]:
            if slot not in by_slot:
                raise AdSmbError("AD read has a missing original predecessor.")
            row, original = by_slot[slot]
            request = original["manifest"]["params"]["ad_smb_request"]
            if row["state"] != "completed":
                raise AdSmbError("Prior AD read has no settled original result.")
            result = self._recover_durable_result(
                row["task_id"], original["manifest"], original["profile"]
            )
            if result is None or result["issue"] is not None:
                raise AdSmbError("Prior AD local context is unavailable.")
            public = result["packet"]
            if public["prior_local_authentication_ids"] != ids:
                raise AdSmbError("Prior AD local context history changed.")
            observed = project_native_read(
                request,
                canonical_json_bytes(result["terminal"]["result"]),
                client_identity_digest=public["client_identity_digest"],
                credential_binding_digest=public["credential_binding_digest"],
                owned_process_exit_verified=True,
            )
            luid = observed["local_authentication_id"]
            if (
                observed["local_cleanup"] != "verified"
                or observed["state"] not in {"bytes_matched", "open_access_denied"}
                or luid is None
                or luid in ids
            ):
                raise AdSmbError(
                    "Prior AD local context cannot establish finite fresh-read history."
                )
            ids.append(luid)
        return ids

    def _revalidate_original(
        self, request: Mapping[str, Any], enrollment: RunnerEnrollment, packet: WorkerPacket
    ) -> None:
        self._recheck_effect_trust(request, enrollment)
        self._verified_runner_binary_digest()
        self.channel.assert_current(_now())
        row = self._execute_row(str(request["task_id"]))
        if (
            row is None
            or row["state"] != "running"
            or not row["effect_dispatched"]
            or row["cancellation_requested"]
            or row["executor_instance"] != self.instance_id
        ):
            raise AdSmbError("AD original reservation is no longer active.")
        original = self._row_context(dict(row))
        if (
            original["manifest"] != request["payload"]["manifest"]
            or original["profile"] != request["payload"]["profile"]
        ):
            raise AdSmbError("AD original reservation changed before delivery.")
        self._context(original["manifest"], original["profile"])
        if (
            self._prior_luids(str(request["task_id"]))
            != packet.to_dict()["prior_local_authentication_ids"]
        ):
            raise AdSmbError("AD original local authentication history changed.")

    def _execute_payload(
        self,
        request: Mapping[str, Any],
        enrollment: RunnerEnrollment,
        manifest: Mapping[str, Any],
        profile: Mapping[str, Any],
        *,
        peer_fingerprint: str | None = None,
        service_grant: Any = None,
        windows_correction_descriptor: Any = None,
        enrollment_binding: Mapping[str, str] | None = None,
    ) -> tuple[Mapping[str, Any], bool]:
        if (
            service_grant is not None
            or windows_correction_descriptor is not None
            or peer_fingerprint is None
        ):
            raise _RequestRefusal("request_invalid")
        if not isinstance(self._runner_binary, Path):
            raise _RequestRefusal("request_invalid")
        original = self._context(manifest, profile)
        self._recheck_effect_trust(request, enrollment)
        task_id = original["task_id"]
        prior = self._recover_durable_result(task_id, manifest, profile)
        if prior is not None:
            self._mark_effect_dispatched(task_id)
            return {"result": prior}, False
        reading = self.channel.to_dict()["role"] == "client"
        credentials = self._ad_credentials
        step = original["manifest"]["params"]["ad_smb_request"]
        if reading and type(credentials) is not CredentialBinding:
            raise _RequestRefusal("request_invalid")
        credential_digest, upn = (
            credentials.reader_binding(step["target"]["reader"])
            if reading and credentials is not None
            else (None, None)
        )
        packet = prepare_packet(
            original,
            self.channel,
            challenge=secrets.token_hex(32),
            credential_binding_digest=credential_digest,
            expected_upn_sha256=upn,
            prior_local_authentication_ids=self._prior_luids(task_id),
            clock=_now(),
        )
        private = credentials.one_use(packet) if reading and credentials is not None else None
        cancellation = threading.Event()
        try:
            with self._verified_runner_binary_guard():
                if not self._enter_effect_dispatch(task_id, cancellation):
                    raise _RequestRefusal("task_cancelled")
                outcome = run_worker(
                    packet,
                    runner_binary=self._runner_binary,
                    runner_digest=self.channel.to_dict()["runner_binary_digest"],
                    work_root=Path(profile["sandbox_root"]),
                    credential=private,
                    revalidate_original=lambda: self._revalidate_original(
                        request, enrollment, packet
                    ),
                    cancellation_event=cancellation,
                )
            if (
                outcome.terminal is None
                or outcome.cleanup != "verified"
                or outcome.dispatch != "attempted"
            ):
                return self._post_dispatch_resolution(task_id)
            checked = self._validated_execute_result(
                result_record(
                    packet,
                    outcome.terminal,
                    native_digest=self.channel.to_dict()["runner_binary_digest"],
                    issue=outcome.issue,
                    receiver_completed_at=_now().isoformat(),
                ),
                manifest,
                profile,
            )
            self._commit_durable_result(task_id, checked)
            return {"result": checked}, False
        except _RequestRefusal:
            raise
        except Exception:
            return self._post_dispatch_resolution(task_id)
        finally:
            with self._task_cancellations_lock:
                if self._task_cancellations.get(task_id) is cancellation:
                    del self._task_cancellations[task_id]

    def _reconcile_execute_task_attempt(self, task_id: str) -> dict[str, Any] | None:
        row = self._execute_row(task_id)
        if row is None or row["operation"] != "execute" or not row["effect_dispatched"]:
            return AuthenticatedRunnerServer._reconcile_execute_task_attempt(self, task_id)
        state, updated = str(row["state"]), int(row["updated_at"])
        result = None
        try:
            original = self._row_context(dict(row))
            result = self._recover_durable_result(
                task_id, original["manifest"], original["profile"]
            )
        except (AdSmbError, RunnerTransportError):
            pass
        if result is not None:
            if not self._set_reconciled_completion(
                task_id, result, expected_state=state, expected_updated_at=updated
            ):
                return None
            return {"state": "completed", "result": result, "receipt_ids": []}
        committed = self._set_execute_recovery_state(
            task_id, receipt_ids=[], expected_state=state, expected_updated_at=updated
        )
        if committed is None:
            return None
        return {"state": committed[0], "result": None, "receipt_ids": committed[1]}

    def _cleanup_reconciled_watchdog(self, task_id: str) -> None:
        # AD has no ordinary runner watchdog files and no filesystem receipts
        # that could establish remote cleanup after a lost terminal.
        return None
