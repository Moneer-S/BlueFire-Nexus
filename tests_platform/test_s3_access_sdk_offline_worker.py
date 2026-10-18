"""Explicit subprocess-only SDK compatibility probe with no network authority."""

from __future__ import annotations

import hashlib
import io
import json
import os
import sys
from datetime import datetime
from html import escape
from pathlib import Path
from types import ModuleType, SimpleNamespace
from urllib.parse import parse_qs, quote, unquote, urlsplit

AUDIT_OFFLINE_FILES = (
    "bluefire/s3_access_runtime.py",
    "bluefire/s3_access_contract.py",
    "bluefire/s3_access_policy.py",
    "bluefire/s3_access_wire.py",
    "bluefire/s3_access_wire_contract.py",
    "bluefire/s3_access_audit.py",
    "bluefire/s3_audit_read_contract.py",
    "bluefire/s3_access_sdk.py",
    "bluefire/s3_access_sdk_boundary.py",
    "bluefire/s3_access_sdk_transport.py",
    "bluefire/s3_audit_sdk.py",
    "bluefire/s3_audit_send.py",
    "bluefire/s3_audit_wire.py",
    "bluefire/s3_audit_collection_contract.py",
    "bluefire/s3_fixture_contract.py",
    "bluefire/s3_fixture_sdk.py",
    "bluefire/s3_fixture_send.py",
    "bluefire/util.py",
    "tests_platform/test_s3_access_sdk_offline_worker.py",
    "tests_platform/s3_audit_offline_responses.py",
    "tests_platform/test_s3_audit_sdk_integration.py",
)


def run_offline() -> dict:
    counters = {
        "socket_construction_denied": 0,
        "network_connection_denied": 0,
        "ambient_reads_denied": 0,
        "credential_resolver_denied": 0,
    }
    original_home = os.environ.get("BLUEFIRE_TEST_ORIGINAL_HOME", "")

    def audit(event, args):
        if event in {
            "socket.__new__",
            "socket.connect",
            "socket.connect_ex",
            "socket.bind",
            "socket.sendto",
            "socket.getaddrinfo",
            "socket.gethostbyname",
        }:
            counters[
                (
                    "socket_construction_denied"
                    if event == "socket.__new__"
                    else "network_connection_denied"
                )
            ] += 1
            raise RuntimeError("offline network boundary")
        if (
            event in {"open", "os.listdir", "os.scandir"}
            and args
            and isinstance(args[0], (str, bytes, os.PathLike))
        ):
            name = os.fsdecode(args[0]).replace("\\", "/").lower()
            if (
                "/.aws" in name
                or name.endswith("/.boto")
                or (os.name == "nt" and name.endswith("/dev/null"))
                or (
                    original_home
                    and name.startswith(original_home.replace("\\", "/").lower() + "/.aws")
                )
            ):
                counters["ambient_reads_denied"] += 1
                raise RuntimeError("offline ambient configuration boundary")

    sys.addaudithook(audit)
    payload = json.loads(sys.stdin.buffer.read(128 * 1024))
    repository = Path(payload["repository"])
    audit_request = payload["request"]["schema_version"] == "bluefire.s3-worker-request.v3"

    def verify_audit_sources():
        if not audit_request:
            return
        assert set(payload["source_pins"]) == set(AUDIT_OFFLINE_FILES)
        for name, expected in payload["source_pins"].items():
            path = repository / name
            assert path.is_file() and not path.is_symlink()
            with path.open("rb") as stream:
                raw = stream.read(1024 * 1024 + 1)
            assert len(raw) <= 1024 * 1024 and hashlib.sha256(raw).hexdigest() == expected

    verify_audit_sources()
    fixed_factory = None
    if payload["scenario"] == "fixed_session":
        # This case exercises the actual fixed Session configuration, not
        # Linux deployment admission. Only those filesystem/import checks are
        # replaced: the SDK-only runtime is independently hash-checked outside.
        package = ModuleType("bluefire")
        package.__path__ = [str(repository / "bluefire")]
        sys.modules["bluefire"] = package
        from bluefire.s3_access_runtime import S3Runtime

        sdk_root = Path(sys.prefix) / "Lib" / "site-packages"
        assert sdk_root.is_dir()
        os.environ.clear()
        runtime = S3Runtime(
            Path(sys.prefix),
            Path(sys.executable),
            Path(sys.base_prefix) / "Lib",
            sdk_root,
            repository / "bluefire",
            "sha256:" + "0" * 64,
            "sha256:" + "0" * 64,
            b"{}",
        )
        S3Runtime.assert_current = lambda self: None

        def component_import_check(self):
            assert sys.flags.isolated and sys.dont_write_bytecode and not os.environ

        S3Runtime._admit_imports = component_import_check
        fixed_factory = runtime.create_factory()
    # SDK imports happen only after denial hooks; only explicit synthetic
    # credentials are passed below. No SDK credential resolver is admissible.
    import botocore.credentials
    import botocore.session
    from botocore.config import Config
    from botocore.exceptions import ClientError
    from urllib3.response import HTTPResponse

    if os.name == "nt":
        assert not Path("/dev/null").exists(), "offline config sentinel is not inert"
    # Component-only loading avoids unrelated product/PyYAML dependencies in
    # this SDK-only venv. Repository roots never enter the SDK import path.
    package = ModuleType("bluefire")
    package.__path__ = [str(repository / "bluefire")]
    sys.modules["bluefire"] = package

    from bluefire.s3_access_contract import S3AccessScope
    from bluefire.s3_access_sdk import S3SdkAdapter
    from bluefire.s3_access_sdk_boundary import BotocoreFactory
    from bluefire.s3_access_wire import S3Credentials, S3WorkerRequest
    from bluefire.s3_fixture_contract import object_metadata
    from bluefire.s3_fixture_contract import payload as fixture_payload
    from bluefire.util import canonical_json_bytes

    def deny_resolver(*_args, **_kwargs):
        counters["credential_resolver_denied"] += 1
        raise RuntimeError("offline credential resolver boundary")

    botocore.credentials.create_credential_resolver = deny_resolver
    botocore.session.Session.get_credentials = deny_resolver
    row = payload["request"]
    request = S3WorkerRequest.from_mapping(row)
    scope = S3AccessScope.from_mapping(row["scope"])
    now = datetime.fromisoformat(payload["now"])
    secret = S3Credentials.from_mapping(
        payload["credentials"],
        clock=lambda: now,
        deadline=datetime.fromisoformat(row["deadline"].replace("Z", "+00:00")),
    )
    policy = payload["policy"]
    http_calls = []
    session_name = ""
    reader = "probe" if row["operation"] == "probe_read" else "legitimate"
    scenario = payload["scenario"]
    opened_sessions = []
    private_config = repository.parent / "s3-sdk-offline-empty-config"
    fixture_objects = {}
    if row["schema_version"] == "bluefire.s3-worker-request.v2" and (
        row["operation"] == "reconcile_fixture" or row["fixture"]["expected_etag"] is not None
    ):
        obj = next(
            obj for obj in row["scope"]["objects"] if obj["purpose"] == row["fixture"]["purpose"]
        )
        fixture_objects[obj["key"]] = {
            "body": fixture_payload(row["scope"]["scope_id"], obj["purpose"]),
            "metadata": object_metadata(row["scope"], row["fixture"]),
            "etag": '"owned-token"',
        }

    def response(body, *, status=200, media="application/xml", identifier=True, extra=None):
        headers = {"content-type": media, "content-length": str(len(body))}
        if identifier:
            headers["x-amz-request-id"] = "offline-request-id"
        if extra:
            headers.update(extra)
        return HTTPResponse(
            body=io.BytesIO(body),
            status=status,
            headers=headers,
            preload_content=False,
            decode_content=False,
        )

    def identity_response(role, session):
        name = row["scope"]["roles"][role].rsplit("/", 1)[1]
        account = row["scope"]["account_id"]
        content = f"<Arn>arn:aws:sts::{account}:assumed-role/{name}/{session}</Arn><UserId>AROAFFFFFFFFFFFFFFFF:{session}</UserId><Account>{account}</Account>"
        return query_response("GetCallerIdentity", content)

    def query_response(operation, content):
        return response(
            (
                f'<{operation}Response xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><{operation}Result>{content}</{operation}Result><ResponseMetadata><RequestId>offline-request-id</RequestId></ResponseMetadata></{operation}Response>'
            ).encode()
        )

    audit_probe = None
    if audit_request:
        assert fixed_factory is not None
        helpers = ModuleType("tests_platform")
        helpers.__path__ = [str(repository / "tests_platform")]
        sys.modules["tests_platform"] = helpers
        from bluefire import s3_audit_collection_contract as audit_contract
        from bluefire import s3_audit_wire as audit_wire
        from tests_platform.s3_audit_offline_responses import AuditOfflineResponses

        audit_probe = AuditOfflineResponses(
            row, payload, audit_contract.list_parameters(scope, row["audit"]), response
        )

    def fixture_response(method, target, arguments):
        parsed = urlsplit(target)
        query = parse_qs(parsed.query, keep_blank_values=True)
        if query == {"versioning": [""]}:
            assert method == "GET"
            return response(
                b'<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"/>'
            )
        if query == {"object-lock": [""]}:
            assert method == "GET"
            return response(
                b"<Error><Code>ObjectLockConfigurationNotFoundError</Code><RequestId>offline-request-id</RequestId></Error>",
                status=404,
            )
        if query.get("list-type") == ["2"]:
            assert method == "GET" and query == {
                "list-type": ["2"],
                "prefix": [row["scope"]["prefix"]],
                "max-keys": ["3"],
                "encoding-type": ["url"],
            }
            contents = "".join(
                f"<Contents><Key>{escape(quote(key, safe=''))}</Key><Size>{len(value['body'])}</Size><ETag>{escape(value['etag'])}</ETag></Contents>"
                for key, value in fixture_objects.items()
            )
            return response(
                (
                    f'<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>{row["scope"]["bucket"]}</Name><Prefix>{escape(quote(row["scope"]["prefix"], safe=""))}</Prefix><EncodingType>url</EncodingType><MaxKeys>3</MaxKeys><KeyCount>{len(fixture_objects)}</KeyCount><IsTruncated>false</IsTruncated>{contents}</ListBucketResult>'
                ).encode()
            )
        assert not query
        prefix = "/" + row["scope"]["bucket"] + "/"
        assert parsed.path.startswith(prefix)
        key = unquote(parsed.path[len(prefix) :])
        assert key in {obj["key"] for obj in row["scope"]["objects"]}
        headers = {
            str(name).lower(): value.decode("ascii") if isinstance(value, bytes) else value
            for name, value in arguments["headers"].items()
        }
        if method == "PUT":
            assert key not in fixture_objects and headers["if-none-match"] == "*"
            assert headers["expect"] == "100-continue"
            body = arguments["body"].read(65537)
            assert body == fixture_payload(row["scope"]["scope_id"], row["fixture"]["purpose"])
            fixture_objects[key] = {
                "body": body,
                "metadata": object_metadata(row["scope"], row["fixture"]),
                "etag": '"owned-token"',
            }
            return response(
                b"", extra={"etag": '"owned-token"', "x-amz-server-side-encryption": "AES256"}
            )
        if method == "DELETE":
            assert headers["content-length"] == "0" and not arguments["body"]
            assert headers["if-match"] == fixture_objects[key]["etag"]
            del fixture_objects[key]
            return response(b"", status=204)
        assert method == "GET"
        if key not in fixture_objects:
            return response(
                b"<Error><Code>NoSuchKey</Code><RequestId>offline-request-id</RequestId></Error>",
                status=404,
            )
        obj = fixture_objects[key]
        return response(
            obj["body"],
            media="application/x-ndjson",
            extra={
                "etag": obj["etag"],
                "x-amz-server-side-encryption": "AES256",
                **{"x-amz-meta-" + key: value for key, value in obj["metadata"].items()},
            },
        )

    class Connection:
        def __init__(self, host):
            self.host = host

        def urlopen(self, **arguments):
            nonlocal policy, session_name
            assert arguments["preload_content"] is False and arguments["decode_content"] is False
            assert arguments["retries"].total is False
            method, target = arguments["method"], arguments["url"]
            http_calls.append({"method": method, "target": target, "host": self.host})
            if audit_probe is not None:
                return audit_probe.urlopen(self.host, arguments, len(http_calls))
            if self.host == scope.service_hosts["sts"]:
                body = arguments["body"]
                fields = parse_qs(
                    body.decode("ascii") if isinstance(body, bytes) else body, strict_parsing=True
                )
                operation = fields["Action"][0]
                if operation == "GetCallerIdentity":
                    authorization = arguments["headers"]["Authorization"].decode("ascii")
                    if payload["credentials"]["access_key"] in authorization:
                        return identity_response("controller", "controller-session")
                    return identity_response(reader, session_name)
                assert operation == "AssumeRole"
                session_name = fields["RoleSessionName"][0]
                name = row["scope"]["roles"][reader].rsplit("/", 1)[1]
                account = row["scope"]["account_id"]
                expiry = payload["credentials"]["expires_at"]
                content = f"<Credentials><AccessKeyId>ASIARRRRRRRRRRRRRRRR</AccessKeyId><SecretAccessKey>{'R' * 40}</SecretAccessKey><SessionToken>{'R' * 64}</SessionToken><Expiration>{expiry}</Expiration></Credentials><AssumedRoleUser><Arn>arn:aws:sts::{account}:assumed-role/{name}/{session_name}</Arn><AssumedRoleId>AROAFFFFFFFFFFFFFFFF:{session_name}</AssumedRoleId></AssumedRoleUser>"
                return query_response(operation, content)
            assert self.host == scope.service_hosts["s3"]
            if row["schema_version"] == "bluefire.s3-worker-request.v2":
                return fixture_response(method, target, arguments)
            if target.endswith("?policy"):
                if method == "PUT":
                    policy = json.loads(arguments["body"])
                    return response(b"", status=204, identifier=scenario != "missing_put_id")
                return response(canonical_json_bytes(policy), media="application/json")
            if scenario == "denied":
                return response(
                    b"<Error><Code>AccessDenied</Code><Message>synthetic denial</Message><RequestId>offline-request-id</RequestId></Error>",
                    status=403,
                )
            if scenario == "redirect":
                return response(
                    b"<Error><Code>PermanentRedirect</Code><Message>synthetic redirect</Message><Endpoint>other.example</Endpoint></Error>",
                    status=301,
                    extra={"location": "https://other.example/"},
                )
            index = [
                "/" + row["scope"]["bucket"] + "/" + obj["key"] for obj in row["scope"]["objects"]
            ].index(target)
            body = payload["objects"][index].encode("utf-8")
            if scenario == "object_drift":
                body = b"x" * len(body)
            if scenario == "oversized":
                body = b"x" * 65537
            return response(
                body, media="application/octet-stream", identifier=scenario != "missing_read_id"
            )

    create_client = botocore.session.Session.create_client

    def offline_client(self, *args, **kwargs):
        client = create_client(self, *args, **kwargs)
        transport = client._endpoint.http_session
        manager = SimpleNamespace(connection_from_url=lambda url: Connection(url.split("/", 3)[2]))
        transport._get_connection_manager = lambda *_args, **_kwargs: manager
        opened_sessions.append(transport)
        return client

    botocore.session.Session.create_client = offline_client

    # None of these paths exists or carries credentials. The audited SDK must
    # neither read the original user's .aws tree nor invoke its resolver.
    if scenario == "hostile_profile":
        os.environ.update(
            AWS_PROFILE="not-enrolled",
            AWS_SHARED_CREDENTIALS_FILE=str(private_config / ".aws" / "credentials"),
            AWS_CONFIG_FILE=str(private_config / ".aws" / "config"),
        )
    factory = fixed_factory or BotocoreFactory(
        session_factory=botocore.session.Session,
        config_factory=Config,
        client_error_type=ClientError,
        ca_bundle=str(Path(botocore.__file__).parent / "cacert.pem"),
        assert_runtime=lambda: None,
    )
    permits = []

    def permit(send):
        if audit_probe is not None:
            audit_wire.validate_send(
                row, send, sequence=len(permits) + 1, committed_discovery=audit_probe.durable
            )
        permits.append(send)
        return {
            "kind": "permit",
            **{key: send[key] for key in ("request_digest", "sequence", "send_digest")},
        }

    audit_options = {}
    if audit_probe is not None:

        def discovery(frame):
            durable = audit_wire.discovery(
                row, frame, reservation_digest=audit_probe.reservation_digest
            )
            return audit_probe.discovery_ack(frame, durable)

        audit_options = {
            "discovery": discovery,
            "audit_reservation_digest": audit_probe.reservation_digest,
        }
    adapter = S3SdkAdapter(
        request, secret, factory=factory, permit=permit, clock=lambda: now, **audit_options
    )
    result = adapter.execute()
    audit_checks = None
    if audit_probe is not None:
        bodies = [
            body for client in adapter.clients for body in client._endpoint.http_session.bodies
        ]
        assert len(bodies) == len(http_calls)
        assert all(body.closed and body.complete for body in bodies)
        receipts = adapter.guard._audit._receipts
        assert all(
            receipt["body_sha256"] == audit_probe.response_hashes[number]
            for number, receipt in receipts.items()
        )
        assert [audit_probe.response_hashes[index] for index in range(1, len(bodies) + 1)] == [
            "sha256:" + body.body_sha256 for body in bodies
        ]
        loaded = {
            Path(module.__file__).resolve().relative_to(repository.resolve()).as_posix()
            for name, module in sys.modules.items()
            if name.startswith(("bluefire.", "tests_platform."))
            and getattr(module, "__file__", None)
        }
        assert loaded <= set(AUDIT_OFFLINE_FILES)
        verify_audit_sources()
        audit_checks = {
            "sts_bodies_verified": audit_probe.sts_bodies_verified,
            "signing": audit_probe.signing,
            "conditional_gets": audit_probe.gets,
            "discovery_acknowledged": audit_probe.acknowledged,
            "list_body_sha256": audit_probe.list_body_hash,
            "compressed_sha256": "sha256:" + hashlib.sha256(audit_probe.packed).hexdigest(),
            "expanded_sha256": "sha256:" + hashlib.sha256(audit_probe.raw).hexdigest(),
            "all_bodies_closed": True,
            "all_bodies_eof": True,
            "wire_body_receipts_match": True,
            "source_before_after_unchanged": True,
        }
    return {
        "result": result,
        "counters": counters,
        "http_calls": len(http_calls),
        "permits": len(permits),
        "send_projections": [frame["send"] for frame in permits],
        "sdk_version": botocore.__version__,
        "transport_mode": "official-sdk-with-inert-connection",
        "production_runtime_admitted": False,
        "session_configuration": "fixed-runtime" if fixed_factory else "injected-test-session",
        **({"audit_checks": audit_checks} if audit_probe is not None else {}),
    }


if __name__ == "__main__":
    try:
        outcome = run_offline()
    except BaseException:
        print(json.dumps({"probe_failed": True, "reason": "offline_sdk_compatibility_failure"}))
        raise SystemExit(1) from None
    print(json.dumps(outcome, separators=(",", ":")))
