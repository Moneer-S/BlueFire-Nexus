"""Bounded API route and query parsing, without service dispatch authority.

Authentication, origin checks, body parsing and dispatch remain in the HTTP shell.
An invalid recognized route preserves its existing sentinel and error response.
"""

from __future__ import annotations

import re
from http import HTTPStatus
from urllib.parse import parse_qsl, urlsplit

from .api_context import API_PREFIX, RouteRequest

_RUN_ID = re.compile(r"^run-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{16}$")
_JOB_ID = re.compile(r"^job-[0-9a-f]{32}$")
_DETECTION_ID = re.compile(r"^detection-[0-9a-f]{20}$")
_PROPOSAL_RECORD_ID = re.compile(r"^proposal-review-[0-9a-f]{32}$")
_MANAGEMENT_IDENTIFIER = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$")
_ACTION_PACKAGE_VERSION = re.compile(
    r"^(0|[1-9][0-9]*)\."
    r"(0|[1-9][0-9]*)\."
    r"(0|[1-9][0-9]*)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$"
)
_SEMVER_CORE_MAX = (1 << 64) - 1
_SCENARIO_VERSION = re.compile(r"^[1-9][0-9]{0,9}$")
_RESOURCE_ROUTE_KINDS = {
    "actions": "action",
    "collectors": "collector",
    "comparisons": "comparison",
    "detection-backends": "detection_backend",
    "detections": "detection",
    "model-providers": "model_provider",
    "plugins": "plugin",
    "research-sources": "research_source",
    "runner-profiles": "runner_profile",
    "runners": "runner",
}


def _valid_management_identifier(value: str) -> bool:
    return 1 <= len(value) <= 200 and _MANAGEMENT_IDENTIFIER.fullmatch(value) is not None


def _valid_action_package_version(value: str) -> bool:
    if not 1 <= len(value) <= 128:
        return False
    match = _ACTION_PACKAGE_VERSION.fullmatch(value)
    if match is None:
        return False
    if any(int(match.group(index)) > _SEMVER_CORE_MAX for index in (1, 2, 3)):
        return False
    prerelease = match.group(4)
    return prerelease is None or not any(
        part.isdigit() and len(part) > 1 and part.startswith("0") for part in prerelease.split(".")
    )


class APIRoutes:
    """Parse routes using only a borrowed request path and error responder."""

    def __init__(self, request: RouteRequest) -> None:
        self.request = request

    @property
    def path(self) -> str:
        return self.request.path

    def _error(self, status: int, code: str, message: str) -> None:
        self.request._error(status, code, message)

    def _run_detail_id(self, path: str) -> str | None:
        prefix = f"{API_PREFIX}/runs/"
        if not path.startswith(prefix):
            return None
        run_id = path[len(prefix) :]
        if "/" in run_id:
            return None
        if not _RUN_ID.fullmatch(run_id):
            self._error(HTTPStatus.BAD_REQUEST, "invalid_run_id", "Run identifier is invalid.")
            return ""
        return run_id

    def _job_detail_id(self, path: str) -> str | None:
        prefix = f"{API_PREFIX}/jobs/"
        if not path.startswith(prefix):
            return None
        job_id = path[len(prefix) :]
        if "/" in job_id:
            return None
        if not _JOB_ID.fullmatch(job_id):
            self._error(HTTPStatus.BAD_REQUEST, "invalid_job_id", "Job identifier is invalid.")
            return ""
        return job_id

    def _job_action_request(self, path: str) -> tuple[str, str] | None:
        prefix = f"{API_PREFIX}/jobs/"
        if not path.startswith(prefix):
            return None
        remainder = path[len(prefix) :]
        parts = remainder.split("/")
        if len(parts) != 2 or parts[1] not in {
            "approval",
            "pause",
            "resume",
            "cancel",
            "retry",
            "detection-revision-decisions",
        }:
            return None
        if not _JOB_ID.fullmatch(parts[0]):
            self._error(HTTPStatus.BAD_REQUEST, "invalid_job_id", "Job identifier is invalid.")
            return ("", parts[1])
        if parts[1] == "detection-revision-decisions" and not self._management_query_free():
            return ("", parts[1])
        return parts[0], parts[1]

    def _proposal_review_request(
        self,
        path: str,
    ) -> tuple[str, str | None, str | None] | None:
        prefix = f"{API_PREFIX}/jobs/"
        if not path.startswith(prefix):
            return None
        parts = path[len(prefix) :].split("/")
        if len(parts) < 2 or parts[1] != "proposals":
            return None
        if len(parts) not in {2, 3, 4} or any(not part for part in parts):
            self._error(
                HTTPStatus.BAD_REQUEST,
                "invalid_proposal_path",
                "Proposal review path is invalid.",
            )
            return ("", None, None)
        job_id = parts[0]
        if not _JOB_ID.fullmatch(job_id):
            self._error(HTTPStatus.BAD_REQUEST, "invalid_job_id", "Job identifier is invalid.")
            return ("", None, None)
        if len(parts) == 2:
            return job_id, None, None
        proposal_record_id = parts[2]
        if not _PROPOSAL_RECORD_ID.fullmatch(proposal_record_id):
            self._error(
                HTTPStatus.BAD_REQUEST,
                "invalid_proposal_id",
                "Proposal review identifier is invalid.",
            )
            return ("", None, None)
        if len(parts) == 3:
            return job_id, proposal_record_id, None
        action = parts[3]
        if action not in {"accept", "reject"}:
            self._error(
                HTTPStatus.BAD_REQUEST,
                "invalid_proposal_action",
                "Proposal review action must be accept or reject.",
            )
            return ("", None, None)
        return job_id, proposal_record_id, action

    def _management_query_free(self) -> bool:
        parsed = urlsplit(self.path)
        if parsed.query or parsed.fragment:
            self._error(
                HTTPStatus.BAD_REQUEST,
                "invalid_management_query",
                "Management routes do not accept query parameters or fragments.",
            )
            return False
        return True

    def _action_package_request(
        self,
        path: str,
    ) -> tuple[str | None, str | None, str | None] | None:
        collection = f"{API_PREFIX}/action-packages"
        if path == collection:
            if not self._management_query_free():
                return ("", None, None)
            return (None, None, None)
        prefix = collection + "/"
        if not path.startswith(prefix):
            return None
        if not self._management_query_free():
            return ("", None, None)
        parts = path[len(prefix) :].split("/")
        if len(parts) == 1 and parts[0]:
            package_id = parts[0]
            version = None
            action = None
        elif len(parts) == 4 and all(parts) and parts[1] == "versions":
            package_id = parts[0]
            version = parts[2]
            action = parts[3]
        else:
            self._error(
                HTTPStatus.BAD_REQUEST,
                "invalid_action_package_path",
                "Action-package path is invalid.",
            )
            return ("", None, None)
        if not _valid_management_identifier(package_id):
            self._error(
                HTTPStatus.BAD_REQUEST,
                "invalid_action_package_id",
                "Action-package ID must be a stable lowercase identifier of at most 200 characters.",
            )
            return ("", None, None)
        if version is None:
            return (package_id, None, None)
        if not _valid_action_package_version(version):
            self._error(
                HTTPStatus.BAD_REQUEST,
                "invalid_action_package_version",
                "Action-package version must be canonical semantic versioning.",
            )
            return ("", None, None)
        if action not in {"activate", "deactivate", "remove"}:
            self._error(
                HTTPStatus.BAD_REQUEST,
                "invalid_action_package_action",
                "Action-package action must be activate, deactivate, or remove.",
            )
            return ("", None, None)
        return (package_id, version, action)

    def _action_package_publisher_request(
        self,
        path: str,
    ) -> tuple[str | None, str | None, str | None] | None:
        collection = f"{API_PREFIX}/action-package-publishers"
        if path == collection:
            if not self._management_query_free():
                return ("", None, None)
            return (None, None, None)
        prefix = collection + "/"
        if not path.startswith(prefix):
            return None
        if not self._management_query_free():
            return ("", None, None)
        parts = path[len(prefix) :].split("/")
        if len(parts) != 4 or any(not part for part in parts) or parts[1] != "keys":
            self._error(
                HTTPStatus.BAD_REQUEST,
                "invalid_action_package_publisher_path",
                "Action-package publisher path is invalid.",
            )
            return ("", None, None)
        publisher_id, key_id, action = parts[0], parts[2], parts[3]
        if not _valid_management_identifier(publisher_id):
            self._error(
                HTTPStatus.BAD_REQUEST,
                "invalid_action_package_publisher_id",
                "Publisher ID must be a stable lowercase identifier of at most 200 characters.",
            )
            return ("", None, None)
        if not _valid_management_identifier(key_id):
            self._error(
                HTTPStatus.BAD_REQUEST,
                "invalid_action_package_key_id",
                "Publisher key ID must be a stable lowercase identifier of at most 200 characters.",
            )
            return ("", None, None)
        if action not in {"suspend", "revoke"}:
            self._error(
                HTTPStatus.BAD_REQUEST,
                "invalid_action_package_publisher_action",
                "Publisher trust action must be suspend or revoke.",
            )
            return ("", None, None)
        return (publisher_id, key_id, action)

    def _action_package_route_allow(self, path: str) -> str | None:
        package_request = self._action_package_request(path)
        if package_request is not None:
            package_id, version, _action = package_request
            if package_id == "":
                return ""
            if package_id is None:
                return "GET, POST"
            return "GET" if version is None else "POST"
        publisher_request = self._action_package_publisher_request(path)
        if publisher_request is not None:
            publisher_id, _key_id, _action = publisher_request
            return "" if publisher_id == "" else "POST"
        return None

    def _setting_key(self, path: str) -> str | None:
        prefix = f"{API_PREFIX}/settings/"
        if not path.startswith(prefix):
            return None
        key = path[len(prefix) :]
        if not self._management_query_free():
            return ""
        if not _valid_management_identifier(key):
            self._error(
                HTTPStatus.BAD_REQUEST,
                "invalid_setting_key",
                "Setting key must be a stable lowercase identifier of at most 200 characters.",
            )
            return ""
        return key

    def _scenario_version_request(self, path: str) -> tuple[str, int | None] | None:
        prefix = f"{API_PREFIX}/scenario-versions/"
        if not path.startswith(prefix):
            return None
        if not self._management_query_free():
            return ("", None)
        parts = path[len(prefix) :].split("/")
        if len(parts) == 1:
            scenario_id, version_raw = parts[0], None
        elif len(parts) == 3 and parts[1] == "versions":
            scenario_id, version_raw = parts[0], parts[2]
        else:
            self._error(
                HTTPStatus.BAD_REQUEST,
                "invalid_scenario_version_path",
                "Scenario-version path is invalid.",
            )
            return ("", None)
        if not _valid_management_identifier(scenario_id):
            self._error(
                HTTPStatus.BAD_REQUEST,
                "invalid_scenario_id",
                "Scenario ID must be a stable lowercase identifier of at most 200 characters.",
            )
            return ("", None)
        if version_raw is None:
            return scenario_id, None
        if not _SCENARIO_VERSION.fullmatch(version_raw):
            self._error(
                HTTPStatus.BAD_REQUEST,
                "invalid_scenario_version",
                "Scenario version must be a positive decimal integer.",
            )
            return ("", None)
        version = int(version_raw, 10)
        if version > 2**31 - 1:
            self._error(
                HTTPStatus.BAD_REQUEST,
                "invalid_scenario_version",
                "Scenario version must be a positive 32-bit integer.",
            )
            return ("", None)
        return scenario_id, version

    def _resource_request(self, path: str) -> tuple[str, str | None] | None:
        prefix = f"{API_PREFIX}/resources/"
        if not path.startswith(prefix):
            return None
        if not self._management_query_free():
            return ("", None)
        parts = path[len(prefix) :].split("/")
        if len(parts) not in {1, 2} or any(not part for part in parts):
            self._error(
                HTTPStatus.BAD_REQUEST,
                "invalid_resource_path",
                "Resource path is invalid.",
            )
            return ("", None)
        kind = _RESOURCE_ROUTE_KINDS.get(parts[0])
        if kind is None:
            self._error(
                HTTPStatus.BAD_REQUEST,
                "invalid_resource_kind",
                "Resource kind is not managed by this API.",
            )
            return ("", None)
        if len(parts) == 1:
            return kind, None
        resource_id = parts[1]
        if not _valid_management_identifier(resource_id):
            self._error(
                HTTPStatus.BAD_REQUEST,
                "invalid_resource_id",
                "Resource ID must be a stable lowercase identifier of at most 200 characters.",
            )
            return ("", None)
        return kind, resource_id

    def _detection_request(self, path: str) -> tuple[str | None, str | None] | None:
        collection = f"{API_PREFIX}/detections"
        if path == collection:
            if not self._management_query_free():
                return ("", None)
            return (None, None)
        prefix = collection + "/"
        if not path.startswith(prefix):
            return None
        if not self._management_query_free():
            return ("", None)
        parts = path[len(prefix) :].split("/")
        if len(parts) not in {1, 2} or any(not part for part in parts):
            self._error(
                HTTPStatus.BAD_REQUEST,
                "invalid_detection_path",
                "Detection lifecycle path is invalid.",
            )
            return ("", None)
        candidate_id = parts[0]
        if not _DETECTION_ID.fullmatch(candidate_id):
            self._error(
                HTTPStatus.BAD_REQUEST,
                "invalid_detection_id",
                "Detection candidate identifier is invalid.",
            )
            return ("", None)
        if len(parts) == 1:
            return (candidate_id, None)
        action = parts[1]
        if action not in {
            "evaluate-run",
            "evaluations",
            "clone",
            "tune",
            "revise-source",
            "ai-revision-jobs",
            "compare",
            "parse",
            "exercise-fixtures",
            "exercise-observed",
            "evaluate-benign",
            "reject",
        }:
            self._error(
                HTTPStatus.BAD_REQUEST,
                "invalid_detection_action",
                "Detection lifecycle action is invalid.",
            )
            return ("", None)
        return (candidate_id, action)

    def _resource_action_request(self, path: str) -> tuple[str, str, str] | None:
        prefix = f"{API_PREFIX}/resources/"
        if not path.startswith(prefix):
            return None
        parts = path[len(prefix) :].split("/")
        if len(parts) != 3 or parts[0] not in {
            "model-providers",
            "plugins",
            "runner-profiles",
        }:
            return None
        if not self._management_query_free():
            return ("", "", "")
        kind = _RESOURCE_ROUTE_KINDS[parts[0]]
        resource_id = parts[1]
        action = parts[2]
        if not _valid_management_identifier(resource_id):
            self._error(
                HTTPStatus.BAD_REQUEST,
                "invalid_resource_id",
                "Resource ID must be a stable lowercase identifier of at most 200 characters.",
            )
            return ("", "", "")
        allowed_actions = {"activate", "deactivate"}
        if kind == "runner_profile":
            allowed_actions.add("probe")
        if action not in allowed_actions:
            self._error(
                HTTPStatus.BAD_REQUEST,
                "invalid_resource_action",
                "Runtime resource action is invalid.",
            )
            return ("", "", "")
        return kind, resource_id, action

    def _run_replay_preparation_id(self, path: str) -> str | None:
        prefix = f"{API_PREFIX}/runs/"
        suffix = "/replay-preparations"
        if not path.startswith(prefix) or not path.endswith(suffix):
            return None
        if not self._management_query_free():
            return ""
        run_id = path[len(prefix) : -len(suffix)]
        if not _RUN_ID.fullmatch(run_id):
            self._error(HTTPStatus.BAD_REQUEST, "invalid_run_id", "Run identifier is invalid.")
            return ""
        return run_id

    def _run_replay_job_id(self, path: str) -> str | None:
        prefix = f"{API_PREFIX}/runs/"
        suffix = "/replay-jobs"
        if not path.startswith(prefix) or not path.endswith(suffix):
            return None
        if not self._management_query_free():
            return ""
        run_id = path[len(prefix) : -len(suffix)]
        if not _RUN_ID.fullmatch(run_id):
            self._error(HTTPStatus.BAD_REQUEST, "invalid_run_id", "Run identifier is invalid.")
            return ""
        return run_id

    def _run_replay_submission_resolution_id(self, path: str) -> str | None:
        prefix = f"{API_PREFIX}/runs/"
        suffix = "/replay-submission-resolution"
        if not path.startswith(prefix) or not path.endswith(suffix):
            return None
        if not self._management_query_free():
            return ""
        run_id = path[len(prefix) : -len(suffix)]
        if not _RUN_ID.fullmatch(run_id):
            self._error(HTTPStatus.BAD_REQUEST, "invalid_run_id", "Run identifier is invalid.")
            return ""
        return run_id

    def _run_replay_id(self, path: str) -> str | None:
        prefix = f"{API_PREFIX}/runs/"
        suffix = "/replays"
        if not path.startswith(prefix) or not path.endswith(suffix):
            return None
        run_id = path[len(prefix) : -len(suffix)]
        if not _RUN_ID.fullmatch(run_id):
            self._error(HTTPStatus.BAD_REQUEST, "invalid_run_id", "Run identifier is invalid.")
            return ""
        return run_id

    def _run_events_request(self, path: str) -> tuple[str, int, int] | None:
        prefix = f"{API_PREFIX}/runs/"
        suffix = "/events"
        if not path.startswith(prefix) or not path.endswith(suffix):
            return None
        run_id = path[len(prefix) : -len(suffix)]
        if not _RUN_ID.fullmatch(run_id):
            self._error(HTTPStatus.BAD_REQUEST, "invalid_run_id", "Run identifier is invalid.")
            return ("", 0, 250)
        try:
            pairs = parse_qsl(
                urlsplit(self.path).query,
                keep_blank_values=True,
                strict_parsing=True,
                max_num_fields=2,
            )
        except ValueError:
            self._error(
                HTTPStatus.BAD_REQUEST,
                "invalid_event_page",
                "Event pagination query parameters are invalid.",
            )
            return ("", 0, 250)
        values: dict[str, str] = {}
        for key, value in pairs:
            if key not in {"after_sequence", "limit"} or key in values:
                self._error(
                    HTTPStatus.BAD_REQUEST,
                    "invalid_event_page",
                    "Event pagination accepts one after_sequence and one limit value.",
                )
                return ("", 0, 250)
            values[key] = value
        after_raw = values.get("after_sequence", "0")
        limit_raw = values.get("limit", "250")
        if (
            not after_raw.isascii()
            or not after_raw.isdigit()
            or not limit_raw.isascii()
            or not limit_raw.isdigit()
        ):
            self._error(
                HTTPStatus.BAD_REQUEST,
                "invalid_event_page",
                "Event pagination values must be non-negative decimal integers.",
            )
            return ("", 0, 250)
        after_sequence = int(after_raw, 10)
        limit = int(limit_raw, 10)
        if after_sequence > 2**63 - 1 or not 1 <= limit <= 1_000:
            self._error(
                HTTPStatus.BAD_REQUEST,
                "invalid_event_page",
                "Event pagination requires after_sequence <= 2^63-1 and limit between 1 and 1000.",
            )
            return ("", 0, 250)
        return run_id, after_sequence, limit
