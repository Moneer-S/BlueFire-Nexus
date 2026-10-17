"""Finite audit collection over the existing guarded SDK, never ambient access."""

from __future__ import annotations

import hashlib
import re
import zlib
from datetime import datetime
from typing import Any, Mapping

from . import s3_audit_collection_contract as audit
from . import s3_audit_wire as wire
from .s3_access_audit import correlate_read_pair
from .s3_access_contract import S3AccessError, document, timestamp
from .s3_access_sdk_boundary import close_body
from .s3_access_wire import S3Credentials, S3WorkerRequest
from .util import content_hash


class AuditSdk:
    def __init__(self, adapter: Any):
        self.adapter = adapter
        self.row = wire.request(adapter.row)
        self.collection = self.row["audit"]
        self.source = self.collection["source"]
        self.limits = audit.budget(adapter.scope, self.source)["per_batch"]
        self.expanded_bytes = 0
        self.events = 0

    def _fresh_collector(self, controller):
        host = self.adapter
        session = "bf-" + self.row["request_id"][:32] + "-collector"
        response = host._call(
            "sts",
            "AssumeRole",
            "controller",
            {
                "RoleArn": self.source["collector_role_arn"],
                "RoleSessionName": session,
                "DurationSeconds": 900,
            },
            controller.assume_role,
        )
        host.guard.response_receipt()
        assumed, raw = response.get("AssumedRoleUser"), response.get("Credentials")
        account = self.row["scope"]["account_id"]
        role = self.source["collector_role_arn"].rsplit("/", 1)[1]
        expected_arn = f"arn:aws:sts::{account}:assumed-role/{role}/{session}"
        if (
            not isinstance(assumed, Mapping)
            or assumed.get("Arn") != expected_arn
            or not isinstance(assumed.get("AssumedRoleId"), str)
            or re.fullmatch(r"[A-Z0-9]{16,64}:" + re.escape(session), assumed["AssumedRoleId"])
            is None
            or not isinstance(raw, Mapping)
            or not isinstance(raw.get("Expiration"), datetime)
        ):
            raise S3AccessError("fresh audit collector session response is invalid")
        credentials = S3Credentials.from_mapping(
            {
                "access_key": raw.get("AccessKeyId"),
                "secret_key": raw.get("SecretAccessKey"),
                "token": raw.get("SessionToken"),
                "expires_at": raw["Expiration"].isoformat(),
            },
            clock=host.clock,
            deadline=timestamp(self.row["deadline"]),
        )
        identity = host._client("sts", credentials)
        observed = host._call(
            "sts", "GetCallerIdentity", "collector", {}, identity.get_caller_identity
        )
        host.guard.response_receipt()
        if (
            observed.get("Account") != account
            or observed.get("Arn") != expected_arn
            or observed.get("UserId") != assumed["AssumedRoleId"]
        ):
            raise S3AccessError("fresh audit collector identity differs from its assumed session")
        return host._client("s3", credentials)

    def _listing(self, client, parameters: Mapping[str, Any]) -> dict[str, Any]:
        host = self.adapter
        response = host._call(
            "s3", "ListObjectsV2", "collector", parameters, client.list_objects_v2
        )
        receipt = host.guard.response_receipt()
        contents = response.get("Contents", [])
        if (
            response.get("Name") != parameters["Bucket"]
            or response.get("Prefix") != parameters["Prefix"]
            or response.get("StartAfter") != parameters["StartAfter"]
            or type(response.get("MaxKeys")) is not int
            or response["MaxKeys"] != parameters["MaxKeys"]
            or type(response.get("KeyCount")) is not int
            or not isinstance(contents, list)
            or response["KeyCount"] != len(contents)
            or not 0 <= len(contents) <= audit.MAX_LIST_KEYS
            or type(response.get("IsTruncated")) is not bool
            or ("EncodingType" in response and response["EncodingType"] != "url")
            or any(
                name in response for name in ("ContinuationToken", "CommonPrefixes", "Delimiter")
            )
            or ("NextContinuationToken" in response and response["IsTruncated"] is not True)
        ):
            raise S3AccessError("audit listing differs from its fixed bounded request")
        rows = []
        for item in contents:
            if not isinstance(item, Mapping):
                raise S3AccessError("audit listing object is invalid")
            rows.append(
                {"key": item.get("Key"), "size_bytes": item.get("Size"), "etag": item.get("ETag")}
            )
        metadata = response["ResponseMetadata"]
        return {
            "prefix": parameters["Prefix"],
            "start_after": parameters["StartAfter"],
            "request_id": metadata["RequestId"],
            "body_sha256": receipt["body_sha256"],
            "http_status": metadata["HTTPStatusCode"],
            "retry_attempts": metadata["RetryAttempts"],
            "key_count": response["KeyCount"],
            "is_truncated": response["IsTruncated"],
            "objects": rows,
        }

    def _object(
        self, client, selected: Mapping[str, Any], index: int
    ) -> tuple[bytes, dict[str, Any]]:
        host = self.adapter
        parameters = {
            "Bucket": self.source["audit_bucket"],
            "ExpectedBucketOwner": self.row["scope"]["account_id"],
            "Key": selected["key"],
            "IfMatch": selected["etag"],
        }
        response = host._call("s3", "GetObject", "collector", parameters, client.get_object)
        try:
            body = response.get("Body")
            if (
                type(response.get("ContentLength")) is not int
                or response["ContentLength"] != selected["size_bytes"]
                or response.get("ETag") != selected["etag"]
                or body is None
            ):
                raise S3AccessError("audit object differs from its committed conditional identity")
            packed = bytearray()
            while True:
                host._checkpoint()
                chunk = body.read(min(8192, selected["size_bytes"] + 1 - len(packed)))
                host._checkpoint()
                if type(chunk) is not bytes:
                    raise S3AccessError("audit object stream is invalid")
                packed.extend(chunk)
                if len(packed) > selected["size_bytes"]:
                    raise S3AccessError("audit object exceeds its committed size")
                if not chunk:
                    break
            receipt = host.guard.response_receipt()
            compressed_digest = "sha256:" + hashlib.sha256(packed).hexdigest()
            if (
                len(packed) != selected["size_bytes"]
                or receipt["sdk_body_bytes"] != len(packed)
                or receipt["body_sha256"] != compressed_digest
            ):
                raise S3AccessError("audit object body differs from its wire receipt")
            remaining = self.limits["expanded_bytes"] - self.expanded_bytes
            host._checkpoint()
            try:
                decoder = zlib.decompressobj(wbits=31)
                raw = decoder.decompress(packed, remaining + 1)
            except zlib.error:
                raise S3AccessError("audit gzip is invalid") from None
            self.expanded_bytes += len(raw)
            host._checkpoint()
            if (
                len(raw) > remaining
                or not raw
                or not decoder.eof
                or decoder.unconsumed_tail
                or decoder.unused_data
            ):
                raise S3AccessError("audit gzip is incomplete, concatenated or oversized")
            parsed = document(raw, limit=remaining)
            if set(parsed) != {"Records"} or not isinstance(parsed["Records"], list):
                raise S3AccessError("audit log must contain only a Records array")
            event_count = len(parsed["Records"])
            self.events += event_count
            if self.events > self.limits["events"]:
                raise S3AccessError("audit events exceed the shared collection bound")
            host._checkpoint()
            return raw, {
                "selected_index": index,
                "compressed_sha256": compressed_digest,
                "expanded_sha256": "sha256:" + hashlib.sha256(raw).hexdigest(),
                "expanded_bytes": len(raw),
                "event_count": event_count,
            }
        finally:
            close_body(response)

    def execute(self, controller) -> dict[str, Any]:
        host = self.adapter
        # The enclosing adapter already checked the controller identity.
        host.guard.response_receipt()
        client = self._fresh_collector(controller)
        listings = [
            self._listing(client, parameters)
            for parameters in audit.list_parameters(host.scope, self.collection)
        ]
        built = audit.discovery(
            host.scope,
            self.collection,
            request_digest=host.request.digest,
            reservation_digest=host.audit_reservation_digest,
            listings=listings,
        )
        host._checkpoint()
        ack = host.discovery(built["frame"])
        durable = host.guard.accept_discovery(
            built["frame"], ack, reservation_digest=host.audit_reservation_digest
        )
        host._checkpoint()
        logs, objects = [], []
        try:
            for index, selected in enumerate(durable["selected"]):
                raw, observed = self._object(client, selected, index)
                logs.append(raw)
                objects.append(observed)
            delivery = "truncated" if durable["truncated"] else "incomplete"
            probe, legitimate = self.collection["original_pair"]["reads"]
            correlated = correlate_read_pair(
                S3WorkerRequest.from_mapping(probe["request"]),
                probe["result"],
                S3WorkerRequest.from_mapping(legitimate["request"]),
                legitimate["result"],
                logs,
                delivery_state=delivery,
            )
            host._checkpoint()
            return {
                "schema_version": wire.OBSERVATION_SCHEMA,
                "collection_digest": content_hash(self.collection),
                "pair_digest": content_hash(self.collection["original_pair"]),
                "audit_source_digest": self.row["audit_authority_digest"],
                "reservation_digest": host.audit_reservation_digest,
                "discovery": durable,
                "objects": objects,
                "usage": {
                    "sdk_body_bytes": host.guard.sdk_body_bytes,
                    "compressed_bytes": host.guard.compressed_bytes,
                    "expanded_bytes": self.expanded_bytes,
                    "events": self.events,
                    "files": len(objects),
                },
                "normalized_digest": content_hash(correlated["audit"]),
                "correlations": correlated["correlations"],
                "delivery_state": delivery,
                "effective_access_claim": False,
                "log_integrity_proven": False,
            }
        finally:
            logs.clear()
