"""Synthetic HTTP responses for the opt-in official audit SDK compatibility test."""

from __future__ import annotations

import gzip
import hashlib
import json
import re
from html import escape
from urllib.parse import parse_qsl, quote, urlsplit


def _digest(value):
    return (
        "sha256:"
        + hashlib.sha256(
            json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
        ).hexdigest()
    )


class AuditOfflineResponses:
    """An inert connection fixture, never a credential or native authority source."""

    def __init__(self, row, payload, list_parameters, response):
        self.row, self.payload, self.response = row, payload, response
        self.source = row["audit"]["source"]
        self.parameters = list_parameters
        assert len(list_parameters) == 1
        assert payload["scenario"] == "fixed_session"
        self.scenario = payload["audit_scenario"]
        assert self.scenario in {"normal", "truncated", "precondition", "wrong_ack"}
        self.raw = payload["audit_log"].encode("utf-8")
        assert len(self.raw) <= 64 * 1024
        self.packed = gzip.compress(self.raw, mtime=0)
        self.key = list_parameters[0]["StartAfter"] + "0000000000000001.json.gz"
        self.etag = '"synthetic-audit-etag"'
        self.reservation_digest = "sha256:" + "8" * 64
        self.session = "bf-" + row["request_id"][:32] + "-collector"
        self.durable = None
        self.acknowledged = False
        self.gets = 0
        self.signing = []
        self.response_hashes = {}
        self.list_body_hash = None
        self.sts_bodies_verified = 0

    def _response(self, body, number, *, status=200, media="application/xml", extra=None):
        self.response_hashes[number] = "sha256:" + hashlib.sha256(body).hexdigest()
        return self.response(
            body,
            status=status,
            media=media,
            extra={"x-amz-request-id": f"audit-request-{number}", **(extra or {})},
        )

    def _query(self, operation, content, number):
        return self._response(
            (
                f'<{operation}Response xmlns="https://sts.amazonaws.com/doc/2011-06-15/">'
                f"<{operation}Result>{content}</{operation}Result><ResponseMetadata>"
                f"<RequestId>audit-request-{number}</RequestId></ResponseMetadata>"
                f"</{operation}Response>"
            ).encode(),
            number,
        )

    def _identity(self, role, number):
        account = self.row["scope"]["account_id"]
        arn = (
            self.source["collector_role_arn"]
            if role == "collector"
            else self.row["scope"]["roles"]["controller"]
        )
        session = self.session if role == "collector" else "controller-session"
        return self._query(
            "GetCallerIdentity",
            f"<Arn>arn:aws:sts::{account}:assumed-role/{arn.rsplit('/', 1)[1]}/{session}</Arn>"
            f"<UserId>AROAFFFFFFFFFFFFFFFF:{session}</UserId><Account>{account}</Account>",
            number,
        )

    def urlopen(self, host, arguments, number):
        method, target = arguments["method"], arguments["url"]
        headers = {
            str(name).lower(): value.decode("ascii") if isinstance(value, bytes) else value
            for name, value in arguments["headers"].items()
        }
        service = "sts" if number <= 3 else "s3"
        region = (
            self.row["scope"]["region"] if service == "sts" else self.source["audit_bucket_region"]
        )
        assert host == f"{service}.{region}.amazonaws.com"
        authorization = headers["authorization"]
        assert re.search(
            r"Credential=[A-Z0-9]+/[0-9]{8}/"
            + re.escape(region + "/" + service)
            + r"/aws4_request(?:,|\s)",
            authorization,
        )
        self.signing.append({"service": service, "region": region, "host": host})
        parsed = urlsplit(target)
        account = self.row["scope"]["account_id"]
        if number <= 3:
            assert method == "POST" and parsed.path == "/" and not parsed.query
            body = arguments["body"]
            body = body.encode("ascii") if isinstance(body, str) else body
            if number in {1, 3}:
                assert body == b"Action=GetCallerIdentity&Version=2011-06-15"
                expected_key = (
                    self.payload["credentials"]["access_key"]
                    if number == 1
                    else "ASIARRRRRRRRRRRRRRRR"
                )
                assert f"Credential={expected_key}/" in authorization
                self.sts_bodies_verified += 1
                return self._identity("controller" if number == 1 else "collector", number)
            expected = (
                "Action=AssumeRole&Version=2011-06-15&RoleArn="
                + quote(self.source["collector_role_arn"], safe="-._~")
                + "&RoleSessionName="
                + self.session
                + "&DurationSeconds=900"
            ).encode()
            assert body == expected
            assert f"Credential={self.payload['credentials']['access_key']}/" in authorization
            self.sts_bodies_verified += 1
            role = self.source["collector_role_arn"].rsplit("/", 1)[1]
            content = (
                "<Credentials><AccessKeyId>ASIARRRRRRRRRRRRRRRR</AccessKeyId>"
                f"<SecretAccessKey>{'R' * 40}</SecretAccessKey><SessionToken>{'R' * 64}</SessionToken>"
                f"<Expiration>{self.payload['credentials']['expires_at']}</Expiration></Credentials>"
                f"<AssumedRoleUser><Arn>arn:aws:sts::{account}:assumed-role/{role}/{self.session}</Arn>"
                f"<AssumedRoleId>AROAFFFFFFFFFFFFFFFF:{self.session}</AssumedRoleId></AssumedRoleUser>"
            )
            return self._query("AssumeRole", content, number)
        assert method == "GET" and not arguments["body"]
        assert headers["x-amz-expected-bucket-owner"] == account
        assert "Credential=ASIARRRRRRRRRRRRRRRR/" in authorization
        assert not any(
            name in headers
            for name in ("range", "if-none-match", "if-modified-since", "if-unmodified-since")
        )
        if number == 4:
            parameters = self.parameters[0]
            pairs = parse_qsl(parsed.query, keep_blank_values=True, strict_parsing=True)
            assert len(pairs) == 5 and dict(pairs) == {
                "list-type": "2",
                "prefix": parameters["Prefix"],
                "start-after": parameters["StartAfter"],
                "max-keys": "16",
                "encoding-type": "url",
            }
            assert parsed.path == "/" + self.source["audit_bucket"]
            truncated = self.scenario == "truncated"
            content = (
                '<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
                f"<Name>{self.source['audit_bucket']}</Name>"
                f"<Prefix>{escape(quote(parameters['Prefix'], safe=''))}</Prefix>"
                f"<StartAfter>{escape(quote(parameters['StartAfter'], safe=''))}</StartAfter>"
                "<EncodingType>url</EncodingType><MaxKeys>16</MaxKeys><KeyCount>1</KeyCount>"
                f"<IsTruncated>{str(truncated).lower()}</IsTruncated>"
                + (
                    "<NextContinuationToken>synthetic-unused-token</NextContinuationToken>"
                    if truncated
                    else ""
                )
                + f"<Contents><Key>{escape(quote(self.key, safe=''))}</Key><Size>{len(self.packed)}</Size>"
                f"<ETag>{escape(self.etag)}</ETag></Contents></ListBucketResult>"
            ).encode()
            self.list_body_hash = "sha256:" + hashlib.sha256(content).hexdigest()
            return self._response(content, number)
        assert number == 5 and self.acknowledged
        assert (
            not parsed.query and parsed.path == "/" + self.source["audit_bucket"] + "/" + self.key
        )
        assert headers["if-match"] == self.etag
        self.gets += 1
        if self.scenario == "precondition":
            return self._response(
                b"<Error><Code>PreconditionFailed</Code><RequestId>audit-request-5</RequestId></Error>",
                number,
                status=412,
            )
        return self._response(
            self.packed, number, media="application/octet-stream", extra={"etag": self.etag}
        )

    def discovery_ack(self, frame, durable):
        assert self.durable is None and len(self.signing) == 4 and self.gets == 0
        assert frame["listings"][0]["body_sha256"] == self.list_body_hash
        assert durable["selected"] == [
            {"key": self.key, "etag": self.etag, "size_bytes": len(self.packed)}
        ]
        self.durable = durable
        ack = {
            "kind": "discovery_committed",
            "request_digest": frame["request_digest"],
            "reservation_digest": self.reservation_digest,
            "discovery_digest": _digest(durable),
            "frame_digest": durable["frame_digest"],
            "next_send_sequence": durable["next_send_sequence"],
        }
        if self.scenario == "wrong_ack":
            ack["discovery_digest"] = "sha256:" + "0" * 64
        else:
            self.acknowledged = True
        return ack
