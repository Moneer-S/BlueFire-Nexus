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
        r"exercises/(job-[0-9a-f]{32})(?:/(review|operations|stop|recover|audit-reviews)(?:/(job-[0-9a-f]{32})(/assistant-context)?)?)?",
        suffix,
    )
    draft = re.fullmatch(r"setup/drafts/([a-z][a-z0-9]*(?:[._-][a-z0-9]+)*)", suffix)
    if (
        suffix
        not in {"environments", "exercises", "setup", "setup/check", "setup/review", "setup/drafts"}
        and match is None
        and draft is None
    ):
        handler._error(
            HTTPStatus.BAD_REQUEST, "s3_access_invalid", "Select a canonical saved S3 exercise."
        )
        return True
    operation, identifier = (match.group(2) or "read", match.group(1)) if match else (suffix, "")
    review_id = match.group(3) if match else None
    if review_id:
        if operation != "audit-reviews":
            handler._error(
                HTTPStatus.BAD_REQUEST,
                "s3_access_invalid",
                "Select a canonical saved audit review.",
            )
            return True
        operation = "audit-assistance" if match and match.group(4) else "audit-review"
    if draft:
        operation, identifier = "setup/draft", draft.group(1)
    service = handler.platform_server.service
    reads = {
        "setup": service.s3_access_setup_profiles,
        "setup/draft": lambda: service.s3_access_saved_setup_draft(identifier),
        "environments": service.s3_access_environments,
        "exercises": service.s3_access_exercises,
        "read": lambda: service.s3_access_exercise(identifier),
        "audit-reviews": lambda: service.s3_audit_reviews(identifier),
        "audit-review": lambda: service.s3_audit_review(identifier, review_id),
        "audit-assistance": lambda: service.s3_audit_assistance_context(identifier, review_id),
    }
    writes = {
        "setup/check": lambda: service.check_s3_access_setup(body),
        "setup/review": lambda: service.review_s3_access_setup_draft(body),
        "setup/drafts": lambda: service.save_s3_access_setup_draft(body),
        "exercises": lambda: service.create_s3_access(body),
        "review": lambda: service.review_s3_access(identifier, body),
        "operations": lambda: service.submit_s3_access(identifier, body),
        "stop": lambda: service.stop_s3_access(identifier, body),
        "recover": lambda: service.recover_s3_access(identifier, body),
        "audit-reviews": lambda: service.save_s3_audit_review(identifier, body),
    }
    choices = reads if body is None else writes
    if operation in choices:
        handler._dispatch(choices[operation])
    else:
        handler._method_not_allowed("POST" if body is None else "GET")
    return True
