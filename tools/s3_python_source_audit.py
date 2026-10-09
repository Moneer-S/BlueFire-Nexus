"""Exact reviewed fixed imports and platform lookups, not a dynamic-call exemption."""

from __future__ import annotations

import hashlib
from typing import Any

_SOURCES = {
    "bluefire/s3_access_host_config.py": (
        "584ad043beab2e597fe938dae53605415c00aa24bed0ffc4914e0dbb9247b6b2",
        ((123, "call", "os.<dynamic>"), (124, "call", "os.<dynamic>")),
    ),
    "bluefire/s3_access_runtime.py": (
        "ce965801943cfc70d2dbca2714fdbac3eb05f859c4a959bd44a0fd984ba09b55",
        (
            (230, "call", "os.<dynamic>"),
            (341, "module", "importlib.metadata"),
            (350, "module", "botocore.session"),
            (351, "module", "botocore.config"),
            (352, "module", "botocore.exceptions"),
            (353, "module", "botocore.loaders"),
            (354, "module", "botocore.credentials"),
            (355, "module", "botocore.tokens"),
            (356, "module", "botocore.history"),
            (358, "module", "bluefire.s3_access_sdk_boundary"),
        ),
    ),
    "bluefire/s3_access_worker_entry.py": (
        "d3f87e0cdf9ad862f42b557db0fb2a02164ba9ef1e3c9b9eb60ceb9afb4ad4c3",
        ((65, "module", "bluefire.s3_access_worker"),),
    ),
}


def s3_python_findings(
    relative: str, source: str, findings: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    reviewed = _SOURCES.get(relative)
    if reviewed is None:
        return findings
    digest, calls = reviewed
    expected = [
        {
            "path": relative,
            "kind": "dynamic_execution_lookup" if field == "call" else "dynamic_shell_import",
            "line": line,
            field: value,
        }
        for line, field, value in calls
    ]
    if hashlib.sha256(source.encode("utf-8")).hexdigest() == digest and findings == expected:
        return []
    return [*findings, {"path": relative, "kind": "reviewed_s3_source_mismatch"}]
