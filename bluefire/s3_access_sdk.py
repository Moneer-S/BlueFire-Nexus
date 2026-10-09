"""Fixed SDK operations behind a future native authority and process boundary."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Callable, Mapping

from .s3_access_contract import S3AccessError, S3AccessScope, timestamp
from .s3_access_policy import (
    S3PolicyChange,
    parse_policy,
    plan_hardening,
    plan_rollback,
    verify_readback,
)
from .s3_access_sdk_boundary import (
    S3ClientFactory,
    S3SendGuard,
    close_body,
    metadata,
    object_digest,
)
from .s3_access_wire import Clock, S3Credentials, S3WorkerRequest, aware_now, validate_result
from .util import canonical_json_bytes, content_hash


class _ServiceFailure(Exception):
    def __init__(self, public: Mapping[str, Any]):
        super().__init__("AWS service refused the scoped request")
        self.public = dict(public)


class S3SdkAdapter:
    """No executable entrypoint. The native owner, not request JSON, supplies the factory."""

    def __init__(
        self,
        request: S3WorkerRequest,
        credentials: S3Credentials,
        *,
        factory: S3ClientFactory,
        permit: Callable[[Mapping[str, Any]], Any],
        clock: Clock,
    ):
        self.request = S3WorkerRequest.from_mapping(request.to_dict())
        self.row = self.request.to_dict()
        self.scope = S3AccessScope.from_mapping(self.row["scope"])
        self.credentials = S3Credentials.from_mapping(
            {
                "access_key": credentials.access_key,
                "secret_key": credentials.secret_key,
                "token": credentials.token,
                "expires_at": credentials.expires_at.isoformat(),
            },
            clock=clock,
            deadline=timestamp(self.row["deadline"]),
        )
        self.factory, self.clock = factory, clock
        self.guard = S3SendGuard(self.request, permit, clock)
        self.calls: list[dict[str, Any]] = []
        self.clients: list[Any] = []
        self._invoked = False

    def _checkpoint(self):
        self.request.assert_current(self.clock)

    def _client(self, service, credentials):
        self._checkpoint()
        remaining = (timestamp(self.row["deadline"]) - aware_now(self.clock)).total_seconds()
        client = self.factory.client(
            service, credentials, self.scope, self.guard, min(5.0, remaining)
        )
        self.clients.append(client)
        return client

    def _call(self, service, operation, role, parameters, method):
        self.guard.begin(service, operation, role, parameters)
        response = None
        try:
            response = method(**parameters)
            self.guard.finish()
            if not isinstance(response, Mapping):
                raise S3AccessError("SDK response is invalid")
            public = metadata(response, success=True, put=operation == "PutBucketPolicy")
            self.calls.append({"operation": operation, "role": role, **public})
            self._checkpoint()
            return response
        except Exception as error:
            close_body(response)
            raw = self.factory.service_error(error)
            if raw is not None:
                close_body(raw)
                self.guard.finish()
                public = metadata(raw, success=False)
                self.calls.append({"operation": operation, "role": role, **public})
                raise _ServiceFailure(public) from None
            raise
        finally:
            self.guard.active = None

    def _identity(self, client, reader, *, expected_user=None, expected_arn=None):
        response = self._call("sts", "GetCallerIdentity", reader, {}, client.get_caller_identity)
        binding = self.scope.to_dict()
        role_name = binding["roles"][reader].rsplit("/", 1)[1]
        prefix = f"arn:aws:sts::{binding['account_id']}:assumed-role/{role_name}/"
        arn, user = response.get("Arn"), response.get("UserId")
        if (
            response.get("Account") != binding["account_id"]
            or not isinstance(arn, str)
            or not arn.startswith(prefix)
            or re.fullmatch(r"[A-Za-z0-9+=,.@_-]{2,64}", arn[len(prefix) :]) is None
            or not isinstance(user, str)
            or re.fullmatch(r"[A-Z0-9]{16,64}:[A-Za-z0-9+=,.@_-]{2,64}", user) is None
        ):
            raise S3AccessError("AWS caller differs from the exact enrolled role and account")
        if user.split(":", 1)[1] != arn[len(prefix) :] or (
            expected_user is not None and (user != expected_user or arn != expected_arn)
        ):
            raise S3AccessError("fresh reader caller differs from its assumed session")

    def _fresh_reader(self, controller, reader):
        binding = self.scope.to_dict()
        session_name = "bf-" + self.row["request_id"][:32] + "-" + reader
        parameters = {
            "RoleArn": binding["roles"][reader],
            "RoleSessionName": session_name,
            "DurationSeconds": 900,
        }
        response = self._call("sts", "AssumeRole", "controller", parameters, controller.assume_role)
        assumed, raw = response.get("AssumedRoleUser"), response.get("Credentials")
        expected_arn = f"arn:aws:sts::{binding['account_id']}:assumed-role/{binding['roles'][reader].rsplit('/', 1)[1]}/{session_name}"
        if (
            not isinstance(assumed, Mapping)
            or assumed.get("Arn") != expected_arn
            or not isinstance(assumed.get("AssumedRoleId"), str)
            or re.fullmatch(r"[A-Z0-9]{16,64}:" + re.escape(session_name), assumed["AssumedRoleId"])
            is None
            or not isinstance(raw, Mapping)
            or not isinstance(raw.get("Expiration"), datetime)
        ):
            raise S3AccessError("fresh reader session response is invalid")
        credentials = S3Credentials.from_mapping(
            {
                "access_key": raw.get("AccessKeyId"),
                "secret_key": raw.get("SecretAccessKey"),
                "token": raw.get("SessionToken"),
                "expires_at": raw["Expiration"].isoformat(),
            },
            clock=self.clock,
            deadline=timestamp(self.row["deadline"]),
        )
        identity = self._client("sts", credentials)
        self._identity(
            identity, reader, expected_user=assumed.get("AssumedRoleId"), expected_arn=expected_arn
        )
        return self._client("s3", credentials)

    def _policy(self, client):
        binding = self.scope.to_dict()
        response = self._call(
            "s3",
            "GetBucketPolicy",
            "controller",
            {"Bucket": binding["bucket"], "ExpectedBucketOwner": binding["account_id"]},
            client.get_bucket_policy,
        )
        value = response.get("Policy")
        if not isinstance(value, str):
            raise S3AccessError("bucket policy response is unavailable")
        return parse_policy(value)

    def _policies(self):
        client = self._client("s3", self.credentials)
        current = self._policy(client)
        if self.row["operation"] == "inspect_policy":
            change = plan_hardening(self.scope, current)
            return {
                "policy_digest": change.to_dict()["before_digest"],
                "structural_review": "supported_baseline",
            }
        change = S3PolicyChange.from_mapping(self.scope, self.row["policy_change"])
        values = change.to_dict()
        if self.row["operation"] == "reconcile_policy":
            current_digest = content_hash(current)
            review = (
                "matched_before"
                if current == values["before"] and current_digest == values["before_digest"]
                else (
                    "matched_after"
                    if current == values["after"] and current_digest == values["after_digest"]
                    else "drift"
                )
            )
            return {"policy_digest": current_digest, "structural_review": review}
        if self.row["operation"] == "apply_policy":
            if current != values["before"] or content_hash(current) != values["before_digest"]:
                raise S3AccessError("policy preimage changed immediately before apply")
            target = values["after"]
        else:
            target = plan_rollback(self.scope, change, current)
        binding = self.scope.to_dict()
        parameters = {
            "Bucket": binding["bucket"],
            "ExpectedBucketOwner": binding["account_id"],
            "Policy": canonical_json_bytes(target).decode("utf-8"),
        }
        self._call("s3", "PutBucketPolicy", "controller", parameters, client.put_bucket_policy)
        observed = self._policy(client)
        if self.row["operation"] == "apply_policy":
            verify_readback(self.scope, change, observed)
        elif observed != values["before"] or content_hash(observed) != values["before_digest"]:
            raise S3AccessError("rollback readback differs from the original policy")
        return {"policy_digest": content_hash(observed), "structural_review": "exact_readback"}

    def _reads(self, controller):
        reader = "probe" if self.row["operation"] == "probe_read" else "legitimate"
        client = self._fresh_reader(controller, reader)
        binding = self.scope.to_dict()
        observations = []
        for obj in binding["objects"][: 1 if reader == "probe" else 2]:
            parameters = {
                "Bucket": binding["bucket"],
                "Key": obj["key"],
                "ExpectedBucketOwner": binding["account_id"],
            }
            try:
                response = self._call("s3", "GetObject", reader, parameters, client.get_object)
                observations.append(
                    {"result": "read", **object_digest(response, obj, self._checkpoint)}
                )
            except _ServiceFailure as failure:
                if (
                    failure.public.get("error_code") != "AccessDenied"
                    or failure.public.get("http_status") != 403
                ):
                    raise
                observations.append({"purpose": obj["purpose"], "result": "service_denied"})
        return {"reader": reader, "objects": observations, "effective_access_claim": False}

    def execute(self) -> dict[str, Any]:
        if self._invoked:
            raise S3AccessError("worker request cannot be executed twice")
        self._invoked = True
        outcome = "failed"
        data: dict[str, Any] | None = None
        problem: str | None = "scoped_operation_failed"
        try:
            self._checkpoint()
            controller = self._client("sts", self.credentials)
            self._identity(controller, "controller")
            data = (
                self._reads(controller)
                if self.row["operation"] in {"probe_read", "legitimate_read"}
                else self._policies()
            )
            outcome, problem = "observed", None
        except Exception:
            if self.guard.write_permitted:
                outcome, problem = "reconcile_required", "write_outcome_unsettled"
        finally:
            for client in self.clients:
                try:
                    client.close()
                except Exception:
                    pass
        return validate_result(
            self.request,
            {
                "schema_version": "bluefire.s3-worker-result.v1",
                "request_digest": self.request.digest,
                "outcome": outcome,
                "data": data,
                "problem": problem,
                "send_permits_consumed": self.guard.sequence,
                "calls": self.calls,
                "runtime_isolation_proven": False,
            },
        )
