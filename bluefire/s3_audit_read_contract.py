"""Pure read-correlation validation and event vocabulary, without wire dispatch."""

from __future__ import annotations

import re
from typing import Any, Mapping

from .s3_access_contract import S3AccessError
from .s3_access_wire_contract import validate_result

_EVENT_ID = re.compile(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}", re.ASCII)
_ERROR_OUTCOMES = {
    "AccessDenied": "service_denied",
    "NoSuchKey": "object_missing",
    "NoSuchBucket": "bucket_missing",
    "ExpiredToken": "credential_error",
    "InvalidToken": "credential_error",
    "InvalidAccessKeyId": "credential_error",
    "SignatureDoesNotMatch": "credential_error",
    "RequestExpired": "credential_error",
    "AuthorizationHeaderMalformed": "credential_error",
}


def validated_read(source: Mapping[str, Any], worker_result: Any) -> dict[str, Any]:
    if source["operation"] not in {"probe_read", "legitimate_read"}:
        raise S3AccessError("audit correlation requires a scoped read request")
    result = validate_result(source, worker_result)
    read_ids = [call["request_id"] for call in result["calls"][3:]]
    if len(set(read_ids)) != len(read_ids) or (
        read_ids and any("error_code" in call for call in result["calls"][:3])
    ):
        raise S3AccessError("worker read identity or unique request mapping is invalid")
    return result
