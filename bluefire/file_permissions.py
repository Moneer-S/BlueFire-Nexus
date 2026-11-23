"""Read-only permission facts from an already opened file's metadata.

POSIX mode bits are not an effective-access calculation: ACLs, directory
traversal, identities and security controls may further restrict access.
"""

from __future__ import annotations

import os
import re
import stat
import sys
from typing import Any, Mapping

PERMISSION_FIELDS = (
    "permission_status",
    "effective_access",
    "permission_mode_octal",
    "group_write_bit",
    "other_write_bit",
    "non_owner_write_bit",
)
PERMISSION_LIMITATION = "permission mode bits only; ACLs, parent-directory traversal and effective access are not evaluated"


def permission_fields_valid(fields: Mapping[str, Any]) -> bool:
    """Validate persisted facts without assuming the verifier's host platform."""
    if fields.get("effective_access") != "not_evaluated":
        return False
    status = fields.get("permission_status")
    if not isinstance(status, str):
        return False
    if status in {"unavailable_windows", "unsupported_platform"}:
        return set(fields) == {"permission_status", "effective_access"}
    mode = fields.get("permission_mode_octal")
    if (
        status != "available"
        or set(fields) != set(PERMISSION_FIELDS)
        or not isinstance(mode, str)
        or re.fullmatch(r"[0-7]{4}", mode) is None
    ):
        return False
    bits = int(mode, 8)
    return (
        fields["group_write_bit"] is bool(bits & stat.S_IWGRP)
        and fields["other_write_bit"] is bool(bits & stat.S_IWOTH)
        and fields["non_owner_write_bit"] is bool(bits & (stat.S_IWGRP | stat.S_IWOTH))
    )


def observed_permission_fields(metadata: os.stat_result) -> dict[str, Any]:
    """Derive no permissions from Windows' synthetic POSIX stat representation."""
    if sys.platform == "win32":
        return {"permission_status": "unavailable_windows", "effective_access": "not_evaluated"}
    if not (sys.platform.startswith("linux") or sys.platform == "darwin"):
        return {"permission_status": "unsupported_platform", "effective_access": "not_evaluated"}
    mode = stat.S_IMODE(metadata.st_mode)
    return {
        "permission_status": "available",
        "effective_access": "not_evaluated",
        "permission_mode_octal": f"{mode:04o}",
        "group_write_bit": bool(mode & stat.S_IWGRP),
        "other_write_bit": bool(mode & stat.S_IWOTH),
        "non_owner_write_bit": bool(mode & (stat.S_IWGRP | stat.S_IWOTH)),
    }
