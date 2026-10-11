"""Exact reviewed fixed imports and platform lookups, not a dynamic-call exemption."""

from __future__ import annotations

import hashlib
from typing import Any

_SOURCES = {
    "bluefire/s3_access_host_config.py": (
        "ee69ad78d79c0b883cf4b855eb76dba7888a82250d20f03d5d01c0791c31bfdd",
        ((26, "call", "os.<dynamic>"), (27, "call", "os.<dynamic>")),
    ),
    "bluefire/s3_access_setup_cli.py": (
        "187c9d57828bbb0ba28c47d5fa4c0bfe125c85d90425378e97b91d6cc8cff59a",
        ((48, "call", "os.<dynamic>"), (62, "call", "os.<dynamic>")),
    ),
    "bluefire/s3_access_runtime.py": (
        "b9bd01ca55c242b289f4746ea287a0c04c95e31842433b42df9fefa4626a1480",
        (
            (233, "call", "os.<dynamic>"),
            (344, "module", "importlib.metadata"),
            (353, "module", "botocore.session"),
            (354, "module", "botocore.config"),
            (355, "module", "botocore.exceptions"),
            (356, "module", "botocore.loaders"),
            (357, "module", "botocore.credentials"),
            (358, "module", "botocore.tokens"),
            (359, "module", "botocore.history"),
            (361, "module", "bluefire.s3_access_sdk_boundary"),
        ),
    ),
    "bluefire/s3_access_worker_entry.py": (
        "4af218c6386f98fa47c1b0dec51e8297a55abc978bbac45d0ca6d9c65337339b",
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
