"""Exact reviewed fixed imports and platform lookups, not a dynamic-call exemption."""

from __future__ import annotations

import hashlib
from typing import Any

_SOURCES = {
    "bluefire/s3_access_host_config.py": (
        "c764761a0420f9b5801cec4ff98f33655323775e14c4891eb6f94b1275170d77",
        ((27, "call", "os.<dynamic>"), (28, "call", "os.<dynamic>")),
    ),
    "bluefire/s3_access_setup_cli.py": (
        "187c9d57828bbb0ba28c47d5fa4c0bfe125c85d90425378e97b91d6cc8cff59a",
        ((48, "call", "os.<dynamic>"), (62, "call", "os.<dynamic>")),
    ),
    "bluefire/s3_access_runtime.py": (
        "8d06eda800888304bba3556aa99641ec5749c4aad27b2f879fdf771cba3fe2fa",
        (
            (240, "call", "os.<dynamic>"),
            (351, "module", "importlib.metadata"),
            (360, "module", "botocore.session"),
            (361, "module", "botocore.config"),
            (362, "module", "botocore.exceptions"),
            (363, "module", "botocore.loaders"),
            (364, "module", "botocore.credentials"),
            (365, "module", "botocore.tokens"),
            (366, "module", "botocore.history"),
            (368, "module", "bluefire.s3_access_sdk_boundary"),
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
