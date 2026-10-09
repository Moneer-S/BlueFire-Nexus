"""Canonical S3 workspace routing under the existing authenticated HTTP shell."""

import re
from http import HTTPStatus
from typing import Any, Mapping

from .api_context import API_PREFIX


def dispatch_s3_access(handler: Any, path: str, body: Mapping[str, Any] | None = None) -> bool:
    prefix = f"{API_PREFIX}/s3-access/"
    if not path.startswith(prefix):
        return False
    if not handler._routes._management_query_free():
        return True
    suffix = path[len(prefix) :]
    match = re.fullmatch(
        r"exercises/(job-[0-9a-f]{32})(?:/(review|operations|stop|recover))?", suffix
    )
    if suffix not in {"environments", "exercises"} and match is None:
        handler._error(
            HTTPStatus.BAD_REQUEST, "s3_access_invalid", "Select a canonical saved S3 exercise."
        )
        return True
    operation, identifier = (match.group(2) or "read", match.group(1)) if match else (suffix, "")
    service = handler.platform_server.service
    reads = {
        "environments": service.s3_access_environments,
        "exercises": service.s3_access_exercises,
        "read": lambda: service.s3_access_exercise(identifier),
    }
    writes = {
        "exercises": lambda: service.create_s3_access(body),
        "review": lambda: service.review_s3_access(identifier, body),
        "operations": lambda: service.submit_s3_access(identifier, body),
        "stop": lambda: service.stop_s3_access(identifier, body),
        "recover": lambda: service.recover_s3_access(identifier, body),
    }
    choices = reads if body is None else writes
    if operation in choices:
        handler._dispatch(choices[operation])
    else:
        handler._method_not_allowed("POST" if body is None else "GET")
    return True
