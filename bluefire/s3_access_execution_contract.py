"""Pure S3 execution result validation; no launcher, storage or credentials."""

from __future__ import annotations

from typing import Any

from .s3_access_contract import S3AccessError, digest, document, exact
from .s3_access_wire import S3WorkerRequest, validate_result


def validate_execution(request: S3WorkerRequest, value: Any) -> dict[str, Any]:
    request = S3WorkerRequest.from_mapping(request.to_dict())
    row = document(value, limit=24 * 1024)
    exact(
        row,
        {
            "schema_version",
            "request_digest",
            "admission",
            "dispatch",
            "send_debits",
            "result",
            "cleanup",
            "provenance",
            "reservation_digest",
        },
        "S3 native execution result",
    )
    if (
        row["schema_version"] != "bluefire.s3-execution.v1"
        or row["request_digest"] != request.digest
    ):
        raise S3AccessError("S3 execution belongs to another request")
    admission = row["admission"]
    exact(admission, {"accepted", "problem"}, "S3 native admission result")
    if type(admission["accepted"]) is not bool:
        raise S3AccessError("S3 admission result is invalid")
    if admission["accepted"]:
        if admission["problem"] is not None:
            raise S3AccessError("accepted S3 admission cannot contain a refusal")
    elif admission["problem"] not in {"runtime_unavailable", "admission_refused", "cancelled"}:
        raise S3AccessError("S3 admission refusal is invalid")
    if (
        row["dispatch"] not in {"not_started", "permit_issued", "unknown"}
        or row["cleanup"] not in {"verified", "unknown"}
        or row["provenance"] not in {"runner_reported", "synthetic"}
        or type(row["send_debits"]) is not int
        or not 0 <= row["send_debits"] <= request.to_dict()["max_sends"]
    ):
        raise S3AccessError("S3 execution state or accounting is invalid")
    if row["reservation_digest"] is not None:
        digest(row["reservation_digest"])
    if not admission["accepted"] and (
        row["dispatch"] != "not_started"
        or row["send_debits"]
        or row["result"] is not None
        or row["reservation_digest"] is not None
    ):
        raise S3AccessError("refused S3 admission cannot claim dispatch")
    if row["send_debits"] and (
        row["dispatch"] == "not_started" or row["reservation_digest"] is None
    ):
        raise S3AccessError("S3 send debit lacks its native reservation")
    if row["dispatch"] == "permit_issued" and row["send_debits"] == 0:
        raise S3AccessError("S3 dispatch has no retained send debit")
    if row["result"] is not None:
        if not admission["accepted"]:
            raise S3AccessError("S3 worker result lacks native admission")
        row["result"] = validate_result(request, row["result"])
        if row["result"]["send_permits_consumed"] > row["send_debits"]:
            raise S3AccessError("worker sends exceed native durable accounting")
    writes = request.to_dict()["operation"] in {"apply_policy", "rollback_policy"}
    observed = row["result"] is not None and row["result"]["outcome"] == "observed"
    if writes and row["send_debits"] >= 3 and not observed and row["dispatch"] != "unknown":
        raise S3AccessError("an unsettled S3 write must require reconciliation")
    return row
