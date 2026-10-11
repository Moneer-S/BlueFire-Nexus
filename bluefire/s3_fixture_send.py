"""Exact prepared S3 fixture requests; no generic transport or new authority."""

from __future__ import annotations

import base64
import hashlib
from typing import Any, Mapping
from urllib.parse import parse_qsl, quote

from .s3_access_contract import S3AccessError
from .s3_fixture_contract import object_metadata, payload, selected_object


def parameters(row: Mapping[str, Any], operation: str) -> dict[str, Any]:
    scope, fixture = row["scope"], row["fixture"]
    base = {"Bucket": scope["bucket"], "ExpectedBucketOwner": scope["account_id"]}
    if operation in {"GetBucketVersioning", "GetObjectLockConfiguration"}:
        return base
    if operation == "ListObjectsV2":
        return {**base, "Prefix": scope["prefix"], "MaxKeys": 3}
    obj = selected_object(scope, fixture)
    result = {**base, "Key": obj["key"]}
    if operation == "PutObject":
        data = payload(scope["scope_id"], fixture["purpose"])
        return {
            **result,
            "Body": data,
            "ContentLength": len(data),
            "ContentType": "application/x-ndjson",
            "ServerSideEncryption": "AES256",
            "IfNoneMatch": "*",
            "Metadata": object_metadata(scope, fixture),
            "ChecksumSHA256": base64.b64encode(hashlib.sha256(data).digest()).decode("ascii"),
        }
    if operation == "DeleteObject":
        return {**result, "IfMatch": fixture["expected_etag"]}
    if operation != "GetObject":
        raise S3AccessError("fixture SDK operation is unsupported")
    return {**result, "ChecksumMode": "ENABLED"}


def prepared_resource(row, active, request, url, body) -> dict[str, Any]:
    scope, fixture = row["scope"], row["fixture"]
    op = active["operation"]
    if active["role"] != "controller" or active["parameters"] != parameters(row, op):
        raise S3AccessError("fixture request differs from its exact reviewed parameters")
    headers = {}
    for name, value in request.headers.items():
        name = str(name).lower()
        if name in headers:
            raise S3AccessError("fixture request has duplicate header identities")
        headers[name] = value.decode("ascii") if isinstance(value, bytes) else value
    expected = {"x-amz-expected-bucket-owner": scope["account_id"]}
    path, query, method = "/" + scope["bucket"], [], "GET"
    resource = {
        "bucket": scope["bucket"],
        "fixture_authority_digest": row["fixture_authority_digest"],
    }
    if op in {"GetBucketVersioning", "GetObjectLockConfiguration"}:
        query = [("versioning" if op == "GetBucketVersioning" else "object-lock", "")]
    elif op == "ListObjectsV2":
        query = [
            ("list-type", "2"),
            ("prefix", scope["prefix"]),
            ("max-keys", "3"),
            ("encoding-type", "url"),
        ]
        resource["prefix"] = scope["prefix"]
        resource["max_keys"] = 3
    else:
        obj = selected_object(scope, fixture)
        path += "/" + quote(obj["key"], safe="/")
        resource.update(key=obj["key"], intent_id=fixture["intent_id"])
        if op == "PutObject":
            method = "PUT"
            expected.update(
                {
                    "if-none-match": "*",
                    "x-amz-server-side-encryption": "AES256",
                    "content-type": "application/x-ndjson",
                    "content-length": str(obj["size_bytes"]),
                    "expect": "100-continue",
                    "x-amz-checksum-sha256": parameters(row, op)["ChecksumSHA256"],
                    **{
                        "x-amz-meta-" + key: value
                        for key, value in object_metadata(scope, fixture).items()
                    },
                }
            )
        elif op == "DeleteObject":
            method = "DELETE"
            expected["if-match"] = fixture["expected_etag"]
            expected["content-length"] = "0"
            resource["expected_etag"] = fixture["expected_etag"]
        elif op == "GetObject":
            expected["x-amz-checksum-mode"] = "ENABLED"
    allowed_transport = {
        "authorization",
        "x-amz-date",
        "x-amz-security-token",
        "x-amz-content-sha256",
        "host",
        "user-agent",
        "amz-sdk-invocation-id",
        "amz-sdk-request",
    }
    if any(name not in expected and name not in allowed_transport for name in headers):
        raise S3AccessError("fixture optional request headers are unsupported")
    if any(headers.get(name) != value for name, value in expected.items()):
        raise S3AccessError(
            "fixture conditional or ownership header differs from its exact binding"
        )
    actual_query = parse_qsl(
        url.query, keep_blank_values=True, strict_parsing=False, max_num_fields=5
    )
    if url.path != path or sorted(actual_query) != sorted(query) or request.method != method:
        raise S3AccessError("fixture endpoint path or method differs from its finite plan")
    expected_body = payload(scope["scope_id"], fixture["purpose"]) if op == "PutObject" else b""
    if body != expected_body:
        raise S3AccessError("fixture request body differs from the canonical payload")
    return resource
