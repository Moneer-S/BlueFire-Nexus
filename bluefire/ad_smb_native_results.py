"""Minimize native read bytes without authenticating their source.

The enrolled adapter must authenticate the original terminal, executable and
channel before calling this parser. Bindings and process-exit evidence come
from that adapter, never the payload. No parser result authorizes dispatch.
"""

from __future__ import annotations

import re
from typing import Any, Mapping

from .ad_smb_contract import AdSmbError, AdSmbReadTarget, AdSmbScope, digest, document, exact, sid
from .ad_smb_results import read_observation


def _uint(value: Any, maximum: int) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise AdSmbError("Native AD integer is outside its exact range.")
    return value


def _optional_bool(value: Any) -> None:
    if value is not None and type(value) is not bool:
        raise AdSmbError("Native AD cleanup state is invalid.")


def project_native_read(
    request: Mapping[str, Any],
    raw: bytes,
    *,
    client_identity_digest: str,
    credential_binding_digest: str,
    owned_process_exit_verified: bool,
) -> dict[str, Any]:
    """Project one closed ReadProof; digests are bindings, not authentication."""
    try:
        return _project_read(
            request,
            raw,
            client_identity_digest=client_identity_digest,
            credential_binding_digest=credential_binding_digest,
            owned_process_exit_verified=owned_process_exit_verified,
        )
    except (KeyError, TypeError, ValueError, IndexError):
        raise AdSmbError(
            "Native AD read result is invalid or differs from its original binding."
        ) from None


def _project_read(
    request: Mapping[str, Any],
    raw: bytes,
    *,
    client_identity_digest: str,
    credential_binding_digest: str,
    owned_process_exit_verified: bool,
) -> dict[str, Any]:
    if type(raw) is not bytes or type(owned_process_exit_verified) is not bool:
        raise AdSmbError("Native AD result requires bytes and separate process evidence.")
    scope = AdSmbScope.from_mapping(request["scope"])
    target = AdSmbReadTarget.from_scope(
        scope, reader=request["target"]["reader"], purpose=request["target"]["file"]["purpose"]
    ).to_dict()
    if (
        request["target"] != target
        or request["scope_digest"] != scope.digest
        or request["step"] != f"read_{target['reader']}_{target['file']['purpose']}"
        or request["phase"] not in {"baseline", "retest"}
        or not isinstance(request["request_id"], str)
        or re.fullmatch(r"[0-9a-f]{32}", request["request_id"]) is None
    ):
        raise AdSmbError("Native AD result target differs from the original request.")
    row = document(raw, limit=16 * 1024)
    exact(
        row,
        {
            "schema_version",
            "request_id",
            "reader",
            "purpose",
            "scope_digest",
            "client_identity_digest",
            "hardened_unc_receipt_digest",
            "credential_binding_digest",
            "expected_remote_sid",
            "state",
            "local_logon",
            "file_open_attempted",
            "protocol",
            "bytes_read",
            "expected_volume_serial",
            "observed_volume_serial",
            "observed_file_id",
            "observed_sha256",
            "failed_stage",
            "win32_error",
            "issue",
            "cleanup",
            "authenticated_remote_reader",
            "fresh_server_logon",
            "independent_observation",
            "effective_access_claim",
        },
        "Native AD read proof",
    )
    expected = {
        "schema_version": "bluefire.ad-smb-fresh-read.v1",
        "request_id": request["request_id"],
        "reader": target["reader"],
        "purpose": target["file"]["purpose"],
        "scope_digest": scope.digest,
        "client_identity_digest": digest(client_identity_digest),
        "credential_binding_digest": digest(credential_binding_digest),
        "hardened_unc_receipt_digest": target["hardened_unc_receipt_digest"],
        "expected_remote_sid": target["expected_remote_sid"],
    }
    if any(row[key] != value for key, value in expected.items()) or any(
        row[key] is not False
        for key in (
            "authenticated_remote_reader",
            "fresh_server_logon",
            "independent_observation",
            "effective_access_claim",
        )
    ):
        raise AdSmbError("Native AD result changed its original binding or asserted extra proof.")
    if (
        row["state"]
        not in {
            "not_started",
            "bytes_matched",
            "open_access_denied",
            "cancelled",
            "deadline",
            "unknown",
        }
        or type(row["file_open_attempted"]) is not bool
    ):
        raise AdSmbError("Native AD read state is invalid.")
    if row["failed_stage"] not in {
        None,
        "caller",
        "logon",
        "impersonate",
        "open",
        "metadata",
        "read",
        "eof",
        "complete",
    }:
        raise AdSmbError("Native AD failure stage is invalid.")
    if row["issue"] is not None and (
        not isinstance(row["issue"], str)
        or re.fullmatch(r"[a-z][a-z0-9_]{0,99}", row["issue"]) is None
    ):
        raise AdSmbError("Native AD issue code is invalid.")
    if row["win32_error"] is not None:
        _uint(row["win32_error"], 2**32 - 1)
    volume = _uint(row["expected_volume_serial"], 2**64 - 1)
    if f"{volume:016x}" != target["file"]["volume_serial"]:
        raise AdSmbError("Native AD expected volume differs from the reviewed target.")
    observed_volume = row["observed_volume_serial"]
    if observed_volume is not None:
        observed_volume = f"{_uint(observed_volume, 2**64 - 1):016x}"
    observed_id = row["observed_file_id"]
    if observed_id is not None and (
        not isinstance(observed_id, str) or re.fullmatch(r"[0-9a-f]{32}", observed_id) is None
    ):
        raise AdSmbError("Native AD observed file identity is invalid.")
    if row["observed_sha256"] is not None:
        digest(row["observed_sha256"])
    count = _uint(row["bytes_read"], target["file"]["size_bytes"])
    local_sid = local_luid = None
    if row["local_logon"] is not None:
        logon = row["local_logon"]
        exact(logon, {"authentication_id", "local_token_user_sid"}, "Native AD local logon")
        local_sid = sid(logon["local_token_user_sid"])
        luid = _uint(logon["authentication_id"], 2**64 - 1)
        local_luid = f"{luid:016x}" if luid else None
    protocol = row["protocol"]
    permitted_protocol = False
    if protocol is not None:
        exact(protocol, {"version", "size", "protocol", "major", "flags"}, "Native SMB protocol")
        for key in ("version", "size", "major"):
            _uint(protocol[key], 2**16 - 1)
        for key in ("protocol", "flags"):
            _uint(protocol[key], 2**32 - 1)
        permitted_protocol = (
            protocol["version"] in {2, 3}
            and protocol["size"] == 116
            and protocol["protocol"] == 0x20000
            and protocol["major"] == 3
            and protocol["flags"] & 0x03 == 0
            and protocol["flags"] & 0x28 == 0x28
            and protocol["flags"] & ~0x3F == 0
        )
    cleanup = row["cleanup"]
    exact(
        cleanup,
        {
            "file_closed",
            "exact_unc_cancel_status",
            "impersonation_reverted",
            "token_closed",
            "observation_tokens_closed",
            "owned_process_exit_required",
            "server_session_closed",
        },
        "Native AD cleanup",
    )
    local_flags = (
        "file_closed",
        "impersonation_reverted",
        "token_closed",
        "observation_tokens_closed",
    )
    for key in local_flags:
        _optional_bool(cleanup[key])
    if (
        type(cleanup["owned_process_exit_required"]) is not bool
        or cleanup["server_session_closed"] is not None
    ):
        raise AdSmbError("Native AD cleanup cannot assert server-session closure.")
    if cleanup["exact_unc_cancel_status"] is not None:
        _uint(cleanup["exact_unc_cancel_status"], 2**32 - 1)
    clean = (
        owned_process_exit_verified
        and not cleanup["owned_process_exit_required"]
        and all(cleanup[key] is not False for key in local_flags)
    )
    state = row["state"]
    if not row["file_open_attempted"] and (
        count != 0
        or any(
            value is not None
            for value in (protocol, observed_volume, observed_id, row["observed_sha256"])
        )
    ):
        raise AdSmbError("Native AD unopened file cannot carry object or content evidence.")
    if state == "not_started" and (
        row["file_open_attempted"]
        or row["local_logon"] is not None
        or row["failed_stage"] is not None
        or row["win32_error"] is not None
        or row["issue"] != "credential_upn_binding_mismatch"
        or any(cleanup[key] is not None for key in local_flags)
        or cleanup["exact_unc_cancel_status"] is not None
        or cleanup["owned_process_exit_required"]
    ):
        raise AdSmbError("Native AD unstarted result contradicts its recorded work.")
    if state in {"bytes_matched", "open_access_denied"} and (
        not row["file_open_attempted"]
        or local_sid is None
        or local_luid is None
        or cleanup["impersonation_reverted"] is not True
        or cleanup["token_closed"] is not True
    ):
        raise AdSmbError("Native AD settled read lacks its local context and cleanup facts.")
    if state == "bytes_matched" and (
        not permitted_protocol
        or cleanup["file_closed"] is not True
        or row["failed_stage"] is not None
        or row["win32_error"] is not None
        or row["issue"] is not None
        or observed_volume != target["file"]["volume_serial"]
        or observed_id != target["file"]["file_id"]
        or count != target["file"]["size_bytes"]
        or row["observed_sha256"] != target["file"]["sha256"]
    ):
        raise AdSmbError("Native AD matched read lacks exact object, content or protocol evidence.")
    if state == "open_access_denied" and (
        row["failed_stage"] != "open"
        or row["win32_error"] != 5
        or row["issue"] != "win32_failure"
        or protocol is not None
        or count != 0
        or any(
            value is not None for value in (observed_volume, observed_id, row["observed_sha256"])
        )
    ):
        raise AdSmbError("Native AD denial was not an exact open denial without consumed data.")
    return read_observation(
        request,
        {
            "request_id": request["request_id"],
            "scope_digest": scope.digest,
            "reader": target["reader"],
            "purpose": target["file"]["purpose"],
            "expected_remote_sid": target["expected_remote_sid"],
            "state": state if clean else "unknown",
            "volume_serial": observed_volume,
            "file_id": observed_id,
            "sha256": row["observed_sha256"],
            "bytes_read": count,
            "local_user_sid": local_sid,
            "local_authentication_id": local_luid,
            "local_cleanup": "verified" if clean else "unknown",
            "server_session_closed": None,
            "authenticated_remote_reader": False,
            "fresh_server_logon": False,
            "independent_observation": False,
            "effective_access_claim": False,
        },
    )
