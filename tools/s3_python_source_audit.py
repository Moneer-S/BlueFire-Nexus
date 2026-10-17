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
        "2d651695721c6175c8070a7f57ad056d09241967eb89893400050f0a17d21b41",
        (
            (238, "call", "os.<dynamic>"),
            (349, "module", "importlib.metadata"),
            (358, "module", "botocore.session"),
            (359, "module", "botocore.config"),
            (360, "module", "botocore.exceptions"),
            (361, "module", "botocore.loaders"),
            (362, "module", "botocore.credentials"),
            (363, "module", "botocore.tokens"),
            (364, "module", "botocore.history"),
            (366, "module", "bluefire.s3_access_sdk_boundary"),
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
