"""Pure resource-row compatibility; no store or filesystem effects."""

import inspect
import json
import sqlite3
from contextlib import closing

import pytest

from bluefire.product_store import ProductStore
from bluefire.product_store_serialization import resource_row


def row(document):
    with closing(sqlite3.connect(":memory:")) as connection:
        connection.row_factory = sqlite3.Row
        return connection.execute(
            "SELECT 's3_setup_draft' AS kind, 'draft-one' AS resource_id, "
            "'draft' AS status, 'original-digest' AS digest, "
            "'original-created' AS created_at, 'original-updated' AS updated_at, "
            "? AS document_json, 'unprojected' AS extra",
            (document,),
        ).fetchone()


@pytest.mark.parametrize("value", [{"name": "\u00e9", "nested": [1, True, None]}, [], None, 7])
def test_resource_projection_preserves_exact_metadata_and_static_surface(value):
    saved = row(json.dumps(value))
    expected = {
        "kind": "s3_setup_draft",
        "id": "draft-one",
        "status": "draft",
        "digest": "original-digest",
        "created_at": "original-created",
        "updated_at": "original-updated",
        "document": value,
    }
    assert isinstance(inspect.getattr_static(ProductStore, "_resource_row"), staticmethod)
    assert resource_row(saved) == ProductStore._resource_row(saved) == expected
    assert list(resource_row(saved)) == list(expected)
    assert saved["extra"] == "unprojected"


@pytest.mark.parametrize(
    "raw,error",
    [
        ("{broken", json.JSONDecodeError),
        ("", json.JSONDecodeError),
        (None, TypeError),
        (7, TypeError),
    ],
)
def test_resource_projection_keeps_decode_errors_visible(raw, error):
    saved = row(raw)
    for decode in (resource_row, ProductStore._resource_row):
        with pytest.raises(error):
            decode(saved)


def test_resource_projection_does_not_share_mutable_decoded_documents():
    saved = row('{"nested": [1]}')
    first = ProductStore._resource_row(saved)
    first["document"]["nested"].append(2)
    assert resource_row(saved)["document"] == {"nested": [1]}


def test_resource_projection_keeps_missing_columns_visible():
    with closing(sqlite3.connect(":memory:")) as connection:
        connection.row_factory = sqlite3.Row
        saved = connection.execute("SELECT 'missing-metadata' AS kind").fetchone()
    for decode in (resource_row, ProductStore._resource_row):
        with pytest.raises(IndexError):
            decode(saved)
