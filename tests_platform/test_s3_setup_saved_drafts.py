"""Workspace persistence is neither host setup nor renewed execution authority."""

import json
from dataclasses import replace

import pytest

from bluefire.application_errors import APIError
from bluefire.product_store import ProductStore
from bluefire.product_store_errors import ProductStoreError
from bluefire.s3_access_setup_drafts import KIND, SCHEMA, read_saved_draft, save_draft
from bluefire.util import content_hash
from tests_platform.test_s3_access_onboarding import configured as configured
from tests_platform.test_s3_access_onboarding import draft_request


@pytest.fixture
def saved_context(configured, tmp_path):
    configured.database = tmp_path / "drafts.sqlite3"
    configured.service.product_store = ProductStore(configured.database)
    configured.save_request = {**draft_request(configured), "expected_digest": None}
    return configured


def test_absence_is_not_a_storage_error(saved_context, monkeypatch):
    ctx = saved_context
    assert read_saved_draft(ctx.service, ctx.profile.id) == {
        "schema_version": SCHEMA,
        "draft": None,
    }
    assert ctx.service.product_store.find_resource(KIND, ctx.profile.id) is None
    with pytest.raises(ProductStoreError, match="not found"):
        ctx.service.product_store.get_resource(KIND, ctx.profile.id)

    def broken(*_args):
        raise ProductStoreError("private storage detail")

    monkeypatch.setattr(ctx.service.product_store, "find_resource", broken)
    with pytest.raises(APIError) as caught:
        read_saved_draft(ctx.service, ctx.profile.id)
    assert caught.value.code == "s3_setup_draft_unavailable"
    assert "private" not in caught.value.message and ctx.calls == []


def test_exact_nonsecret_bytes_survive_store_restart_without_host_effects(saved_context):
    ctx = saved_context
    source = json.loads(ctx.save_request["configuration_json"])
    source["environments"][0]["display_name"] = "Scope caf\u00e9"
    ctx.save_request["configuration_json"] = (
        "\r\n" + json.dumps(source, ensure_ascii=False, indent=2) + "\n"
    )
    saved = save_draft(ctx.service, ctx.save_request)
    assert saved["draft"]["configuration_json"] == ctx.save_request["configuration_json"]
    assert set(saved["draft"]) == {
        "profile_id",
        "profile_digest",
        "configuration_json",
        "digest",
        "updated_at",
    }
    ctx.service.product_store = ProductStore(ctx.database)
    assert read_saved_draft(ctx.service, ctx.profile.id) == saved
    resource = ctx.service.product_store.get_resource(KIND, ctx.profile.id)
    assert resource["status"] == "draft" and "review" not in resource["document"]
    assert ctx.calls == []


def test_same_initial_save_is_idempotent_but_cannot_replace_another_draft(saved_context):
    ctx = saved_context
    saved = save_draft(ctx.service, ctx.save_request)
    assert save_draft(ctx.service, ctx.save_request) == saved
    other = {
        **ctx.save_request,
        "configuration_json": ctx.save_request["configuration_json"] + "\n",
    }
    with pytest.raises(APIError) as caught:
        save_draft(ctx.service, other)
    assert caught.value.code == "s3_setup_draft_changed"
    assert read_saved_draft(ctx.service, ctx.profile.id) == saved and ctx.calls == []


def test_compare_and_save_preserves_the_other_windows_work(saved_context):
    ctx = saved_context
    initial = save_draft(ctx.service, ctx.save_request)
    change = {
        **ctx.save_request,
        "configuration_json": ctx.save_request["configuration_json"] + "\n",
        "expected_digest": initial["draft"]["digest"],
    }
    changed = save_draft(ctx.service, change)
    assert changed["draft"]["digest"] != initial["draft"]["digest"]
    with pytest.raises(APIError) as caught:
        save_draft(
            ctx.service, {**change, "configuration_json": change["configuration_json"] + "\n"}
        )
    assert caught.value.code == "s3_setup_draft_changed"
    assert read_saved_draft(ctx.service, ctx.profile.id) == changed and ctx.calls == []


def test_stale_profile_draft_remains_readable_but_cannot_be_saved_as_current(saved_context):
    ctx = saved_context
    saved = save_draft(ctx.service, ctx.save_request)
    ctx.service._runner_profiles = lambda: ()
    assert read_saved_draft(ctx.service, ctx.profile.id) == saved
    with pytest.raises(APIError) as caught:
        save_draft(ctx.service, {**ctx.save_request, "expected_digest": saved["draft"]["digest"]})
    assert caught.value.code == "s3_setup_profile_changed"
    assert ctx.calls == []


def test_legacy_saved_source_stays_readable_without_implicit_binding(saved_context):
    ctx = saved_context
    source = json.loads(ctx.save_request["configuration_json"])
    source["schema_version"] = "bluefire.s3-host-environments.v1"
    del source["environments"][0]["managed_profile_digest"]
    text = json.dumps(source, indent=2) + "\n"
    payload = {"schema_version": SCHEMA, **ctx.request, "configuration_json": text}
    stored = ctx.service.product_store.save_resource(KIND, ctx.profile.id, payload, status="draft")
    before = read_saved_draft(ctx.service, ctx.profile.id)
    assert before["draft"]["configuration_json"] == text
    with pytest.raises(APIError) as caught:
        save_draft(
            ctx.service,
            {**ctx.request, "configuration_json": text, "expected_digest": stored["digest"]},
        )
    assert caught.value.code == "s3_setup_draft_invalid"
    assert read_saved_draft(ctx.service, ctx.profile.id) == before
    assert ctx.service.product_store.get_resource(KIND, ctx.profile.id) == stored
    assert ctx.calls == []


def test_changed_profile_requires_explicit_source_binding_before_replacement(saved_context):
    ctx = saved_context
    initial = save_draft(ctx.service, ctx.save_request)
    ctx.profile.budgets = replace(ctx.profile.budgets, max_steps=11)
    current = content_hash(ctx.profile.to_dict())
    request = {
        **ctx.save_request,
        "profile_digest": current,
        "expected_digest": initial["draft"]["digest"],
    }
    with pytest.raises(APIError) as caught:
        save_draft(ctx.service, request)
    assert caught.value.code == "s3_setup_draft_invalid"
    assert read_saved_draft(ctx.service, ctx.profile.id) == initial
    source = json.loads(request["configuration_json"])
    source["environments"][0]["managed_profile_digest"] = current
    request["configuration_json"] = json.dumps(source, indent=2) + "\n"
    changed = save_draft(ctx.service, request)
    assert changed["draft"]["profile_digest"] == current
    assert changed["draft"]["configuration_json"] == request["configuration_json"]
    assert changed["draft"]["digest"] != initial["draft"]["digest"]
    assert read_saved_draft(ctx.service, ctx.profile.id) == changed
    assert ctx.calls == []


@pytest.mark.parametrize(
    "mutation",
    ["extra", "secret", "secret_label", "oversize", "wrong_profile", "bad_expected", "stale"],
)
def test_invalid_or_secret_inputs_are_not_retained(saved_context, mutation):
    ctx = saved_context
    request = dict(ctx.save_request)
    if mutation == "extra":
        request["apply"] = True
    elif mutation == "secret":
        source = json.loads(request["configuration_json"])
        source["credentials"] = {"password": "not-accepted"}
        request["configuration_json"] = json.dumps(source)
    elif mutation == "secret_label":
        source = json.loads(request["configuration_json"])
        source["environments"][0]["display_name"] = "sk" + "-" + "X" * 24
        request["configuration_json"] = json.dumps(source)
    elif mutation == "oversize":
        request["configuration_json"] = " " * (128 * 1024 + 1)
    elif mutation == "wrong_profile":
        request["profile_id"] = "../different"
    elif mutation == "bad_expected":
        request["expected_digest"] = True
    else:
        request["profile_digest"] = "sha256:" + "f" * 64
    with pytest.raises(APIError):
        save_draft(ctx.service, request)
    assert ctx.service.product_store.find_resource(KIND, ctx.profile.id) is None
    assert ctx.calls == []


@pytest.mark.parametrize("corruption", ["json", "digest", "status", "secret"])
def test_corrupt_saved_state_is_not_absence_or_a_source_of_plaintext(saved_context, corruption):
    ctx = saved_context
    save_draft(ctx.service, ctx.save_request)
    with ctx.service.product_store._connection(write=True) as connection:
        if corruption == "json":
            connection.execute(
                "UPDATE resources SET document_json = ? WHERE kind = ?", ("{broken", KIND)
            )
        elif corruption == "digest":
            connection.execute(
                "UPDATE resources SET digest = ? WHERE kind = ?", ("sha256:" + "0" * 64, KIND)
            )
        elif corruption == "status":
            connection.execute("UPDATE resources SET status = 'active' WHERE kind = ?", (KIND,))
        else:
            connection.execute(
                "UPDATE resources SET document_json = ? WHERE kind = ?",
                (json.dumps({"credentials": "not-accepted"}), KIND),
            )
        before = tuple(
            connection.execute(
                "SELECT document_json, digest, status FROM resources WHERE kind = ?", (KIND,)
            ).fetchone()
        )
    with pytest.raises(APIError) as caught:
        read_saved_draft(ctx.service, ctx.profile.id)
    assert caught.value.code == "s3_setup_draft_unavailable"
    with ctx.service.product_store._connection() as connection:
        after = tuple(
            connection.execute(
                "SELECT document_json, digest, status FROM resources WHERE kind = ?", (KIND,)
            ).fetchone()
        )
    assert before == after and ctx.calls == []
