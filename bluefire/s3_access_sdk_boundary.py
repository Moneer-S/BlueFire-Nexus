"""Bounded Botocore request/result boundary, without a runtime loader or entrypoint."""

from __future__ import annotations

import hashlib
from typing import Any, Callable, Mapping, Protocol
from urllib.parse import parse_qsl, quote, urlsplit

from .s3_access_contract import S3AccessError, S3AccessScope
from .s3_access_sdk_transport import BoundedSdkTransport
from .s3_access_wire import (
    SAFE_ERROR_CODES,
    SAFE_REQUEST_ID,
    Clock,
    S3Credentials,
    S3WorkerRequest,
    operation_plan,
    permit_request,
    validate_permit,
)
from .util import canonical_json_bytes


class S3ClientFactory(Protocol):
    def client(
        self,
        service: str,
        credentials: S3Credentials,
        scope: S3AccessScope,
        guard: S3SendGuard,
        timeout: float,
    ) -> Any: ...

    def service_error(self, error: Exception) -> Mapping[str, Any] | None: ...


class BotocoreFactory:
    """SDK construction for a future attested loader; never discovers installed code.

    The trusted native integration must supply verified SDK bindings and a runtime
    assertion. No wire field can select a factory, import, executable or test driver.
    There is intentionally no default import or unreviewed installed-version fallback.
    """

    def __init__(
        self,
        *,
        session_factory,
        config_factory,
        client_error_type,
        ca_bundle: str,
        assert_runtime: Callable[[], None],
    ):
        if not ca_bundle or not callable(assert_runtime):
            raise S3AccessError("reviewed SDK runtime is unavailable")
        self._session_factory = session_factory
        self._config_factory = config_factory
        self._client_error_type = client_error_type
        self._ca_bundle = ca_bundle
        self._assert_runtime = assert_runtime

    def client(self, service, credentials, scope, guard, timeout):
        self._assert_runtime()
        if service not in {"sts", "s3"}:
            raise S3AccessError("SDK service is unsupported")
        session = self._session_factory()
        session.set_config_variable("config_file", "/dev/null")
        session.set_config_variable("credentials_file", "/dev/null")
        session.set_config_variable("profile", None)
        config = self._config_factory(
            signature_version="s3v4" if service == "s3" else "v4",
            region_name=scope.to_dict()["region"],
            connect_timeout=timeout,
            read_timeout=timeout,
            proxies={},
            retries={"mode": "standard", "total_max_attempts": 1},
            max_pool_connections=1,
            defaults_mode="legacy",
            ignore_configured_endpoint_urls=True,
            inject_host_prefix=False,
            use_dualstack_endpoint=False,
            use_fips_endpoint=False,
            s3={
                "addressing_style": "path",
                "use_accelerate_endpoint": False,
                "us_east_1_regional_endpoint": "regional",
            },
        )
        client = session.create_client(
            service,
            region_name=scope.to_dict()["region"],
            endpoint_url="https://" + scope.service_hosts[service],
            use_ssl=True,
            verify=self._ca_bundle,
            config=config,
            **credentials.client_arguments(),
        )
        try:
            # This private SDK interface must be checked against the selected,
            # attested release before the future native loader can admit it.
            endpoint = client._endpoint
            endpoint.http_session = BoundedSdkTransport(
                endpoint.http_session,
                guard.claim_transport_send,
                lambda: guard.request.assert_current(guard.clock),
            )
            client.meta.events.register("before-send.*.*", guard.hook)
        except Exception:
            client.close()
            raise S3AccessError("reviewed SDK transport interface is unavailable") from None
        return client

    def service_error(self, error):
        if isinstance(error, self._client_error_type):
            value = error.response
            return value if isinstance(value, Mapping) else None
        return None


def metadata(value: Mapping[str, Any], *, success: bool, put: bool = False) -> dict[str, Any]:
    raw = value.get("ResponseMetadata")
    if not isinstance(raw, Mapping):
        raise S3AccessError("SDK response metadata is unavailable")
    identifier, status = raw.get("RequestId"), raw.get("HTTPStatusCode")
    if (
        not isinstance(identifier, str)
        or SAFE_REQUEST_ID.fullmatch(identifier) is None
        or type(status) is not int
        or raw.get("RetryAttempts") != 0
        or type(raw.get("RetryAttempts")) is not int
    ):
        raise S3AccessError("SDK response metadata is invalid")
    if success and status not in ({200, 204} if put else {200}):
        raise S3AccessError("SDK response status is not confirmed success")
    if not success and not 400 <= status <= 599:
        raise S3AccessError("SDK error status is invalid")
    result = {"request_id": identifier, "http_status": status}
    if not success:
        error = value.get("Error")
        code = error.get("Code") if isinstance(error, Mapping) else None
        result["error_code"] = (
            code if isinstance(code, str) and code in SAFE_ERROR_CODES else "OtherServiceError"
        )
    return result


def close_body(response: Any) -> None:
    if isinstance(response, Mapping) and response.get("Body") is not None:
        try:
            response["Body"].close()
        except Exception:
            pass


def object_digest(
    response: Mapping[str, Any], expected: Mapping[str, Any], checkpoint: Callable[[], None]
) -> dict[str, Any]:
    body = response.get("Body")
    try:
        if (
            type(response.get("ContentLength")) is not int
            or response["ContentLength"] != expected["size_bytes"]
            or body is None
        ):
            raise S3AccessError("object length differs from the exact generated object")
        total, digest = 0, hashlib.sha256()
        while True:
            checkpoint()
            chunk = body.read(min(8192, expected["size_bytes"] + 1 - total))
            if type(chunk) is not bytes:
                raise S3AccessError("object stream is invalid")
            checkpoint()
            if not chunk:
                break
            total += len(chunk)
            if total > expected["size_bytes"]:
                raise S3AccessError("object exceeds its exact byte allowance")
            digest.update(chunk)
        observed = "sha256:" + digest.hexdigest()
        if total != expected["size_bytes"] or observed != expected["sha256"]:
            raise S3AccessError("object bytes differ from the generated object binding")
        return {"purpose": expected["purpose"], "sha256": observed, "size_bytes": total}
    finally:
        close_body(response)


class S3SendGuard:
    def __init__(
        self, request: S3WorkerRequest, permit: Callable[[Mapping[str, Any]], Any], clock: Clock
    ):
        self.request = S3WorkerRequest.from_mapping(request.to_dict())
        self.scope = S3AccessScope.from_mapping(self.request.to_dict()["scope"])
        self.permit, self.clock = permit, clock
        self.sequence = 0
        self.active: dict[str, Any] | None = None
        self.used = False
        self.permitted = False
        self.transport_sent = False
        self.prepared_request: Any = None
        self.prepared_fingerprint = ""
        self.write_permitted = False

    def begin(self, service: str, operation: str, role: str, parameters: Mapping[str, Any]) -> None:
        if self.active is not None:
            raise S3AccessError("concurrent SDK sends are unsupported")
        self.request.assert_current(self.clock)
        plan = operation_plan(self.request)
        if self.sequence >= len(plan) or (service, operation, role) != plan[self.sequence]:
            raise S3AccessError("SDK call differs from the fixed operation sequence")
        if operation == "GetObject":
            position = self.sequence - 3
            if parameters.get("Key") != self.scope.to_dict()["objects"][position]["key"]:
                raise S3AccessError("SDK object order differs from the finite read plan")
        self.active = {
            "service": service,
            "operation": operation,
            "role": role,
            "parameters": dict(parameters),
        }
        self.used = False
        self.permitted = False
        self.transport_sent = False
        self.prepared_request = None
        self.prepared_fingerprint = ""

    def hook(self, request, **_kwargs) -> None:
        self.request.assert_current(self.clock)
        active = self.active
        if active is None or self.used:
            raise S3AccessError("unplanned retry, redirect or SDK request is refused")
        self.used = True
        scope = self.scope.to_dict()
        service, operation, parameters = (
            active["service"],
            active["operation"],
            active["parameters"],
        )
        try:
            url = urlsplit(request.url)
            if (
                url.scheme != "https"
                or url.hostname != self.scope.service_hosts[service]
                or url.port not in (None, 443)
                or url.username is not None
                or url.password is not None
                or url.fragment
            ):
                raise S3AccessError("SDK request endpoint differs from its exact binding")
            body = request.body or b""
            if isinstance(body, str):
                body = body.encode("utf-8")
            if type(body) is not bytes or len(body) > 20 * 1024:
                raise S3AccessError("SDK request body is unsupported")
            resource: dict[str, Any] = {}
            if service == "sts":
                if (
                    operation not in {"GetCallerIdentity", "AssumeRole"}
                    or request.method != "POST"
                    or url.path != "/"
                    or url.query
                ):
                    raise S3AccessError("STS request differs from its fixed operation")
                fields = parse_qsl(
                    body.decode("ascii"),
                    keep_blank_values=True,
                    strict_parsing=True,
                    max_num_fields=6,
                )
                expected = {
                    "Action": operation,
                    "Version": "2011-06-15",
                    **{key: str(value) for key, value in parameters.items()},
                }
                if len(fields) != len(dict(fields)) or dict(fields) != expected:
                    raise S3AccessError("STS parameters differ from the exact operation")
                if operation == "AssumeRole":
                    reader = (
                        "probe"
                        if self.request.to_dict()["operation"] == "probe_read"
                        else "legitimate"
                    )
                    if (
                        parameters
                        != {
                            "RoleArn": scope["roles"][reader],
                            "RoleSessionName": "bf-"
                            + self.request.to_dict()["request_id"][:32]
                            + "-"
                            + reader,
                            "DurationSeconds": 900,
                        }
                        or active["role"] != "controller"
                    ):
                        raise S3AccessError("STS reader session differs from the fixed scope")
                    resource = {
                        "role_arn": parameters["RoleArn"],
                        "session_name": parameters["RoleSessionName"],
                    }
                elif parameters or active["role"] not in {"controller", "probe", "legitimate"}:
                    raise S3AccessError("STS identity parameters are unsupported")
            elif service == "s3":
                if (
                    parameters.get("Bucket") != scope["bucket"]
                    or parameters.get("ExpectedBucketOwner") != scope["account_id"]
                ):
                    raise S3AccessError("S3 expected owner or bucket differs from scope")
                headers = {str(key).lower(): value for key, value in request.headers.items()}
                if any(
                    name in headers
                    for name in (
                        "range",
                        "x-amz-request-payer",
                        "x-amz-server-side-encryption-customer-key",
                        "if-match",
                        "if-none-match",
                        "if-modified-since",
                        "if-unmodified-since",
                    )
                ):
                    raise S3AccessError("S3 optional access parameters are unsupported")
                expected_owner = headers.get("x-amz-expected-bucket-owner")
                if isinstance(expected_owner, bytes):
                    expected_owner = expected_owner.decode("ascii")
                if expected_owner != scope["account_id"]:
                    raise S3AccessError("S3 request lacks its exact expected-owner header")
                path = "/" + scope["bucket"]
                resource = {"bucket": scope["bucket"]}
                if operation == "GetObject":
                    key = parameters.get("Key")
                    if (
                        set(parameters) != {"Bucket", "Key", "ExpectedBucketOwner"}
                        or key not in {obj["key"] for obj in scope["objects"]}
                        or request.method != "GET"
                        or url.query
                        or body
                    ):
                        raise S3AccessError("S3 object request differs from the exact resource")
                    path += "/" + quote(key, safe="/")
                    resource["key"] = key
                elif operation in {"GetBucketPolicy", "PutBucketPolicy"}:
                    if (
                        set(parameters)
                        != (
                            {"Bucket", "ExpectedBucketOwner", "Policy"}
                            if operation == "PutBucketPolicy"
                            else {"Bucket", "ExpectedBucketOwner"}
                        )
                        or active["role"] != "controller"
                    ):
                        raise S3AccessError("S3 policy parameters are unsupported")
                    if parse_qsl(url.query, keep_blank_values=True) != [
                        ("policy", "")
                    ] or request.method != ("PUT" if operation == "PutBucketPolicy" else "GET"):
                        raise S3AccessError("S3 policy request differs from its fixed operation")
                    expected_body = (
                        parameters["Policy"].encode("utf-8")
                        if operation == "PutBucketPolicy"
                        else b""
                    )
                    if body != expected_body:
                        raise S3AccessError("S3 policy body differs from the reviewed document")
                else:
                    raise S3AccessError("S3 operation is unsupported")
                if url.path != path:
                    raise S3AccessError("S3 request path differs from its exact resource")
            else:
                raise S3AccessError("SDK service is unsupported")
        except (ValueError, UnicodeError, AttributeError, KeyError) as exc:
            if isinstance(exc, S3AccessError):
                raise
            raise S3AccessError("SDK prepared request is invalid") from None
        send = {
            "service": service,
            "operation": operation,
            "role": active["role"],
            "method": request.method,
            "host": url.hostname,
            "resource": resource,
            "payload_digest": "sha256:" + hashlib.sha256(body).hexdigest(),
        }
        requested = permit_request(self.request, self.sequence + 1, send)
        validate_permit(self.permit(requested), requested)
        # Native debit precedes ACK. An expired or interrupted worker cannot
        # refund that debit or assume an acknowledged write was not attempted.
        self.sequence += 1
        if operation == "PutBucketPolicy":
            self.write_permitted = True
        self.request.assert_current(self.clock)
        self.permitted = True
        self.prepared_request = request
        self.prepared_fingerprint = self._fingerprint(request)

    @staticmethod
    def _fingerprint(request: Any) -> str:
        body = request.body or b""
        if isinstance(body, str):
            body = body.encode("utf-8")
        if type(body) is not bytes:
            raise S3AccessError("SDK prepared body changed after review")
        headers = []
        for name, value in request.headers.items():
            kind = "text"
            if isinstance(value, bytes):
                kind = "bytes"
                value = value.hex()
            if not isinstance(name, str) or not isinstance(value, str):
                raise S3AccessError("SDK prepared headers are unsupported")
            headers.append([name, kind, value])
        payload = canonical_json_bytes(
            {"method": request.method, "url": request.url, "body": body.hex(), "headers": headers}
        )
        return hashlib.sha256(payload).hexdigest()

    def claim_transport_send(self, request: Any) -> None:
        self.request.assert_current(self.clock)
        if (
            not self.permitted
            or self.transport_sent
            or request is not self.prepared_request
            or self._fingerprint(request) != self.prepared_fingerprint
        ):
            raise S3AccessError("SDK transport has no exact unused send permit")
        self.transport_sent = True

    def finish(self) -> None:
        if not self.permitted or not self.transport_sent:
            raise S3AccessError("SDK client did not pass its required before-send guard")
        self.active = None
