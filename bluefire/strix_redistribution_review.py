"""Fixed, incomplete rights review shared by Strix provenance receipts.

Root project licenses and artifact integrity do not clear bundled third-party
components. Changing this gate requires a separately reviewed rights inventory;
no build or CLI-startup probe can promote it to redistribution readiness.
"""

from __future__ import annotations

from typing import Any

from .util import canonical_json_bytes

STRIX_REDISTRIBUTION_COMPONENT_SCOPES = (
    "third_party_go_tui",
    "bundled_frontend_viewer_assets",
    "complete_python_runtime_wheels",
    "oci_image",
)


def strix_redistribution_review() -> dict[str, Any]:
    """Return a fresh blocked receipt; null denotes an unresolved rights fact."""

    return {
        "schema": "bluefire.strix-redistribution-review.v1",
        "status": "blocked-pending-component-review",
        "redistribution_ready": False,
        "license_review_complete": False,
        "redistribution_authorized": False,
        "root_license_is_component_clearance": False,
        "project_license_attribution": {"bluefire": "MIT", "strix_source": "Apache-2.0"},
        "component_reviews": {
            scope: {
                "review_complete": False,
                "license_expression": None,
                "notices_complete": None,
                "redistribution_rights_confirmed": None,
            }
            for scope in STRIX_REDISTRIBUTION_COMPONENT_SCOPES
        },
    }


def is_blocked_strix_redistribution_review(value: Any) -> bool:
    """Reject omissions, invented clearances, and bool/integer substitutions."""

    try:
        return canonical_json_bytes(value) == canonical_json_bytes(strix_redistribution_review())
    except (TypeError, ValueError):
        return False
