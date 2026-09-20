"""Read-only permission facts from an already opened file's metadata.

POSIX mode bits are not an effective-access calculation: ACLs, directory
traversal, identities and security controls may further restrict access.
"""

from __future__ import annotations

import os
import stat
import sys
from typing import Any

PERMISSION_FIELDS = (
    "permission_status",
    "effective_access",
    "permission_mode_octal",
    "group_write_bit",
    "other_write_bit",
    "non_owner_write_bit",
)
PERMISSION_LIMITATION = "permission mode bits only; ACLs, parent-directory traversal and effective access are not evaluated"


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
