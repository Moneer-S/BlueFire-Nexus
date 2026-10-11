"""Canonical AD workspace routes behind the existing authenticated HTTP shell."""

import re
from http import HTTPStatus
from typing import Any, Mapping
from urllib.parse import urlsplit

from .api_context import API_PREFIX


def dispatch_ad_smb(handler: Any, path: str, body: Mapping[str, Any] | None = None) -> bool:
    prefix = f"{API_PREFIX}/ad-smb/"
    if not path.startswith(prefix):
        return False
    if not handler._routes._management_query_free():
        return True
    if urlsplit(handler.path).path != path:
        handler._error(
            HTTPStatus.BAD_REQUEST, "ad_smb_invalid", "Use the exact saved AD workflow path."
        )
        return True
    suffix = path[len(prefix) :]
    match = re.fullmatch(
        r"workflows/(job-[0-9a-f]{32})(?:/(review|operations|stop|recover))?", suffix
    )
    if suffix not in {"environments", "workflows"} and match is None:
        handler._error(
            HTTPStatus.BAD_REQUEST, "ad_smb_invalid", "Select a canonical saved AD workflow."
        )
        return True
    operation, identifier = (match.group(2) or "read", match.group(1)) if match else (suffix, "")
    service = handler.platform_server.service
    reads = {
        "environments": service.ad_smb_environments,
        "workflows": service.ad_smb_workflows,
        "read": lambda: service.ad_smb_workflow(identifier),
    }
    writes = {
        "workflows": lambda: service.create_ad_smb(body),
        "review": lambda: service.review_ad_smb(identifier, body),
        "operations": lambda: service.submit_ad_smb(identifier, body),
        "stop": lambda: service.stop_ad_smb(identifier, body),
        "recover": lambda: service.recover_ad_smb(identifier, body),
    }
    choices = reads if body is None else writes
    if operation in choices:
        handler._dispatch(choices[operation])
    else:
        handler._method_not_allowed("POST" if body is None else "GET")
    return True
