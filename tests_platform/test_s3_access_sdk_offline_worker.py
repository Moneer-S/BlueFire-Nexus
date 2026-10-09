"""Explicit subprocess-only SDK compatibility probe with no network authority."""

from __future__ import annotations

import io
import json
import os
import sys
from datetime import datetime
from pathlib import Path
from types import ModuleType, SimpleNamespace
from urllib.parse import parse_qs


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

    class Connection:
        def __init__(self, host):
            self.host = host

        def urlopen(self, **arguments):
            nonlocal policy, session_name
            assert arguments["preload_content"] is False and arguments["decode_content"] is False
            assert arguments["retries"].total is False
            method, target = arguments["method"], arguments["url"]
            http_calls.append({"method": method, "target": target, "host": self.host})
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

    class OfflineSession(botocore.session.Session):
        def create_client(self, *args, **kwargs):
            client = super().create_client(*args, **kwargs)
            transport = client._endpoint.http_session
            manager = SimpleNamespace(
                connection_from_url=lambda url: Connection(url.split("/", 3)[2])
            )
            transport._get_connection_manager = lambda *_args, **_kwargs: manager
            opened_sessions.append(transport)
            return client

    # None of these paths exists or carries credentials. The audited SDK must
    # neither read the original user's .aws tree nor invoke its resolver.
    if scenario == "hostile_profile":
        os.environ.update(
            AWS_PROFILE="not-enrolled",
            AWS_SHARED_CREDENTIALS_FILE=str(private_config / ".aws" / "credentials"),
            AWS_CONFIG_FILE=str(private_config / ".aws" / "config"),
        )
    factory = BotocoreFactory(
        session_factory=OfflineSession,
        config_factory=Config,
        client_error_type=ClientError,
        ca_bundle=str(Path(botocore.__file__).parent / "cacert.pem"),
        assert_runtime=lambda: None,
    )
    permits = []

    def permit(send):
        permits.append(send)
        return {
            "kind": "permit",
            **{key: send[key] for key in ("request_digest", "sequence", "send_digest")},
        }

    result = S3SdkAdapter(
        request, secret, factory=factory, permit=permit, clock=lambda: now
    ).execute()
    return {
        "result": result,
        "counters": counters,
        "http_calls": len(http_calls),
        "permits": len(permits),
        "sdk_version": botocore.__version__,
        "transport_mode": "official-sdk-with-inert-connection",
        "production_runtime_admitted": False,
    }


if __name__ == "__main__":
    try:
        outcome = run_offline()
    except BaseException:
        print(json.dumps({"probe_failed": True, "reason": "offline_sdk_compatibility_failure"}))
        raise SystemExit(1) from None
    print(json.dumps(outcome, separators=(",", ":")))
