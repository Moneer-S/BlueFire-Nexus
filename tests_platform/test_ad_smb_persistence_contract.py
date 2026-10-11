"""Opaque public AD references never relax ordinary durable plaintext-secret checks."""

from copy import deepcopy

import pytest

from bluefire.product_store_contracts import safe_document
from bluefire.product_store_errors import ProductStoreError
from tests_platform.test_ad_smb_contract import scope_row


def test_closed_scope_preserves_original_values_and_only_validated_handles():
    scope = scope_row()
    scope["network"]["flows"].reverse()
    original = deepcopy(scope)
    result = safe_document({"nested": [scope]})
    assert result == {"nested": [original]}
    assert scope == original
    result["nested"][0]["principals"]["probe"]["credential_handle"] = "changed"
    assert scope == original


@pytest.mark.parametrize("role", ["controller", "probe", "legitimate"])
@pytest.mark.parametrize(
    "value",
    ["plaintext", "credential-" + "A" * 32, "credential-" + "a" * 31, {"env": "SECRET"}, None],
)
def test_bad_handle_never_enters_store(role, value):
    scope = scope_row()
    scope["principals"][role]["credential_handle"] = value
    with pytest.raises(ProductStoreError, match="invalid protected reference"):
        safe_document(scope)


@pytest.mark.parametrize("location", ["top", "principal", "host", "network", "authentication"])
def test_schema_cannot_hide_extra_nested_values(location):
    scope = scope_row()
    target = {
        "top": scope,
        "principal": scope["principals"]["probe"],
        "host": scope["hosts"]["client"],
        "network": scope["network"],
        "authentication": scope["authentication"],
    }[location]
    target["password"] = "not-persistable"
    with pytest.raises(ProductStoreError, match="invalid protected reference"):
        safe_document(scope)


@pytest.mark.parametrize(
    "value",
    [
        {"credential_handle": "credential-" + "a" * 32},
        {
            "schema_version": "bluefire.ad-smb-scope.v1",
            "credential_handle": "credential-" + "a" * 32,
        },
        {
            "schema_version": "other",
            "principals": {"probe": {"credential_handle": "credential-" + "a" * 32}},
        },
        {
            "value": "https://synthetic:negative@example.test"
        },  # pragma: allowlist secret -- synthetic rejection fixture
    ],
)
def test_scope_exception_does_not_cover_standalone_or_spoofed_secrets(value):
    with pytest.raises(ProductStoreError):
        safe_document(value)
