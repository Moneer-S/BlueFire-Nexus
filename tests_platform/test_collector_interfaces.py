from __future__ import annotations

import pytest

from bluefire.collector_interfaces import (
    BoundedAdapterQuery,
    CloudIdentityAuditAdapter,
    CollectorAdapterError,
    LinuxAuditRuntimeAdapter,
    SecurityQueryAdapter,
    WindowsEventLogAdapter,
)


def test_bounded_adapter_query_accepts_only_opaque_secret_references() -> None:
    query = BoundedAdapterQuery(
        query_template_id="query.identity.signins.v1",
        scope_ref="tenant:test",
        start_at="2026-01-01T00:00:00Z",
        end_at="2026-01-01T00:05:00Z",
        max_records=500,
        max_bytes=1024 * 1024,
        credential_reference="secret-ref:collector.identity.readonly",
    )

    assert query.max_records == 500
    with pytest.raises(CollectorAdapterError, match="opaque secret reference"):
        BoundedAdapterQuery(
            query_template_id="query.identity.signins.v1",
            scope_ref="tenant:test",
            start_at="2026-01-01T00:00:00Z",
            end_at="2026-01-01T00:05:00Z",
            max_records=500,
            max_bytes=1024,
            credential_reference="raw-token-value",
        )


def test_platform_adapter_interfaces_are_explicit_and_separate() -> None:
    assert {
        interface.__name__
        for interface in (
            WindowsEventLogAdapter,
            LinuxAuditRuntimeAdapter,
            CloudIdentityAuditAdapter,
            SecurityQueryAdapter,
        )
    } == {
        "WindowsEventLogAdapter",
        "LinuxAuditRuntimeAdapter",
        "CloudIdentityAuditAdapter",
        "SecurityQueryAdapter",
    }
