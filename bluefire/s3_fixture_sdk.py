"""Fixed conditional fixture calls under the existing bounded SDK send guard."""

from __future__ import annotations

from typing import Any, Mapping

from .s3_access_contract import S3AccessError
from .s3_access_sdk_boundary import S3ServiceFailure, close_body, object_digest
from .s3_fixture_contract import etag, object_metadata, observation, selected_object
from .s3_fixture_send import parameters


class FixtureSdk:
    def __init__(self, adapter: Any):
        self.adapter = adapter
        self.row, self.scope = adapter.row, adapter.row["scope"]
        self.fixture = self.row["fixture"]
        self.obj = selected_object(self.scope, self.fixture)
        self.client = adapter._client("s3", adapter.credentials)

    def _call(self, name, method):
        return self.adapter._call("s3", name, "controller", parameters(self.row, name), method)

    def _shape(self) -> None:
        response = self._call("GetBucketVersioning", self.client.get_bucket_versioning)
        if set(response) != {"ResponseMetadata"}:
            raise S3AccessError("fixture bucket is not observed in the never-versioned shape")
        try:
            self._call("GetObjectLockConfiguration", self.client.get_object_lock_configuration)
        except S3ServiceFailure as error:
            if (error.public["http_status"], error.public["error_code"]) == (
                404,
                "ObjectLockConfigurationNotFoundError",
            ):
                return
            raise
        raise S3AccessError("fixture bucket Object Lock absence was not confirmed")

    def _get(self) -> tuple[str, str | None]:
        try:
            response = self._call("GetObject", self.client.get_object)
        except S3ServiceFailure as error:
            if (error.public["http_status"], error.public["error_code"]) == (404, "NoSuchKey"):
                return "absent", None
            raise
        try:
            token = etag(response.get("ETag"))
            if (
                response.get("Metadata") != object_metadata(self.scope, self.fixture)
                or response.get("ServerSideEncryption") != "AES256"
                or response.get("ContentType") != "application/x-ndjson"
                or any(
                    name in response for name in ("VersionId", "DeleteMarker", "ContentEncoding")
                )
            ):
                return "drift", None
            object_digest(response, self.obj, self.adapter._checkpoint)
            return "owned", token
        except S3AccessError:
            return "drift", None
        finally:
            close_body(response)

    def _listing(self, state: str) -> None:
        response = self._call("ListObjectsV2", self.client.list_objects_v2)
        contents = response.get("Contents", [])
        expected = {obj["key"]: obj for obj in self.scope["objects"]}
        if (
            response.get("IsTruncated") is not False
            or not isinstance(contents, list)
            or len(contents) > 2
            or response.get("Prefix") != self.scope["prefix"]
            or response.get("Name") != self.scope["bucket"]
            or response.get("MaxKeys") != 3
            or type(response.get("KeyCount")) is not int
            or response["KeyCount"] != len(contents)
            or any(
                name in response
                for name in ("NextContinuationToken", "ContinuationToken", "CommonPrefixes")
            )
        ):
            raise S3AccessError("fixture prefix reconciliation is incomplete or unsupported")
        seen = set()
        for obj in contents:
            if (
                not isinstance(obj, Mapping)
                or not isinstance(obj.get("Key"), str)
                or obj["Key"] not in expected
                or obj["Key"] in seen
                or type(obj.get("Size")) is not int
                or obj["Size"] != expected[obj["Key"]]["size_bytes"]
            ):
                raise S3AccessError("fixture prefix contains foreign or changed objects")
            seen.add(obj["Key"])
        if (self.obj["key"] in seen) != (state != "absent"):
            raise S3AccessError("fixture prefix and object readback disagree")

    def execute(self) -> dict[str, Any]:
        self._shape()
        state, token = self._get()
        if self.row["operation"] == "prepare_fixture":
            if state != "absent":
                raise S3AccessError("fixture creation refuses an existing object")
            response = self._call("PutObject", self.client.put_object)
            created = etag(response.get("ETag"))
            if response.get("ServerSideEncryption") != "AES256" or "VersionId" in response:
                raise S3AccessError("fixture create response has an unsupported ownership shape")
            state, token = self._get()
            if state != "owned" or token != created:
                raise S3AccessError("fixture creation lacks exact content and metadata readback")
        elif self.row["operation"] == "cleanup_fixture":
            expected = self.fixture["expected_etag"]
            if expected is None:
                if state != "absent":
                    raise S3AccessError("known-absent cleanup cannot delete an observed object")
            else:
                if state != "owned" or token != expected:
                    raise S3AccessError("fixture cleanup preimage changed")
                response = self._call("DeleteObject", self.client.delete_object)
                if response["ResponseMetadata"]["HTTPStatusCode"] != 204 or any(
                    name in response for name in ("VersionId", "DeleteMarker")
                ):
                    raise S3AccessError(
                        "fixture delete response has an unsupported versioned shape"
                    )
                state, token = self._get()
                if state != "absent":
                    raise S3AccessError("fixture deletion has no confirmed absence readback")
            self._listing(state)
        else:
            if (
                self.fixture["expected_etag"] is not None
                and token != self.fixture["expected_etag"]
                and state == "owned"
            ):
                state, token = "drift", None
            self._listing(state)
        return observation(self.row, state, token)
