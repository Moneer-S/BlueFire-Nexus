"""Synthetic protected provenance, SQLite admission and public read projections."""

from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from types import SimpleNamespace

import pytest

from bluefire import file_access_context
from bluefire import windows_file_access_admission as admission
from bluefire import windows_file_access_context as windows_context
from bluefire import windows_file_access_enrollment as enrollment
from bluefire.file_access_contract import FileAccessContractError
from bluefire.file_access_control import FileAccessControl
from bluefire.product_store import ProductStore
from bluefire.product_store_errors import ProductStoreError
from bluefire.util import canonical_json_bytes, content_hash
from tests_platform.test_windows_file_access_enrollment import observed_setup as observed_setup


@pytest.fixture
def imported_source(observed_setup, tmp_path, monkeypatch):
    _, state, _, row, _ = observed_setup
    checked = enrollment.read_windows_file_access_enrollment(now_ms=state["wall"])
    store = ProductStore(tmp_path / "windows.db")
    service = SimpleNamespace(product_store=store)
    control = FileAccessControl(service, clock=lambda: state["wall"])
    monkeypatch.setattr(file_access_context, "is_windows_host", lambda: True)
    monkeypatch.setattr(windows_context, "read_windows_file_setup_status", lambda **_: checked)
    selection = {"enrollment_id": row["enrollment_id"], "enrollment_digest": content_hash(row)}
    return SimpleNamespace(
        store=store,
        control=control,
        checked=checked,
        selection=selection,
        now=state["wall"],
        state=state,
        row=row,
    )


def counts(store):
    with store._connection() as connection:
        return {
            table: connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
            for table in (
                "jobs",
                "file_access_operations",
                "file_access_task_claims",
                "file_access_revisions",
                "file_access_outcomes",
                "file_access_setup_imports",
            )
        }


def test_explicit_import_is_provenance_only_and_public_reads_are_platform_safe(imported_source):
    source = imported_source
    result = source.control.import_setup(source.selection)
    assert result == source.control.control(result["control_owner_id"])
    assert result["schema_version"] == admission.CONTROL_SCHEMA
    assert result["status"] == "setup_verified" and result["revision"] == 1
    assert result["baseline"] is None and result["operations"] == result["allowed_operations"] == []
    assert result["task_usage_state"] == "none" and result["account_object_cleanup"] == "required"
    assert set(result["resource"]) == {
        "resource_id",
        "resource_generation",
        "expected_sha256",
        "size_bytes",
        "protection",
    }
    assert result["resource"]["protection"] == "reader_readable"
    assert not any(
        value in str(result)
        for value in ("S-1-", "C:\\", "secret-ref", "approved_by", "record_count")
    )
    assert source.control.controls()["controls"] == [
        {
            "control_owner_id": result["control_owner_id"],
            "status": "setup_verified",
            "revision": 1,
            "platform": "windows",
        }
    ]
    assert counts(source.store) == {
        "jobs": 0,
        "file_access_operations": 0,
        "file_access_task_claims": 0,
        "file_access_revisions": 0,
        "file_access_outcomes": 0,
        "file_access_setup_imports": 1,
    }
    assert (
        source.store.get_file_access_control_revision(result["control_owner_id"], 1)[
            "document_digest"
        ]
        == result["control_digest"]
    )


def test_read_only_status_does_not_import_or_create_jobs(imported_source):
    source = imported_source
    from bluefire import windows_file_access_context

    # Reuse the genuine fake-observer result; status does not call any store write.
    source.control.service.windows_file_access_verified = True
    from unittest.mock import patch

    with patch.object(
        windows_file_access_context, "read_windows_file_setup_status", return_value=source.checked
    ):
        assert source.control.status()["setup"] == source.checked.summary()
    assert not any(counts(source.store).values())


def test_exact_replay_after_expiry_is_historical_and_never_reobserves(imported_source, monkeypatch):
    source = imported_source
    original = source.control.import_setup(source.selection)
    source.state["wall"] = source.row["expires_at_ms"] + 100
    monkeypatch.setattr(
        windows_context,
        "read_windows_file_setup_status",
        lambda **_: pytest.fail("historical import replay"),
    )
    assert source.control.import_setup(source.selection) == original
    second = FileAccessControl(
        SimpleNamespace(product_store=ProductStore(source.store.path)),
        clock=lambda: source.state["wall"],
    )
    monkeypatch.setattr(
        windows_context,
        "read_windows_file_setup_status",
        lambda **_: pytest.fail("second-store replay observed native facts"),
    )
    assert second.import_setup(source.selection) == original
    assert (
        source.control.control(original["control_owner_id"])["expires_at_ms"]
        == source.row["expires_at_ms"]
    )
    assert counts(source.store)["file_access_setup_imports"] == 1


@pytest.mark.parametrize(
    "change", ["extra", "digest", "identity", "expired", "rollback", "caller_dict", "linux"]
)
def test_first_import_refuses_stale_or_asserted_setup_without_writes(
    imported_source, monkeypatch, change
):
    source = imported_source
    request = dict(source.selection)
    if change == "extra":
        request["verified"] = True
    elif change == "digest":
        request["enrollment_digest"] = "sha256:" + "0" * 64
    elif change == "identity":
        request["enrollment_id"] = "win-file-enrollment-" + "0" * 32
    elif change == "expired":
        source.state["wall"] = source.row["expires_at_ms"]
    elif change == "rollback":
        source.state["wall"] = source.row["issued_at_ms"] - 1
    elif change == "caller_dict":
        monkeypatch.setattr(
            windows_context, "read_windows_file_setup_status", lambda **_: source.row
        )
    elif change == "linux":
        monkeypatch.setattr(file_access_context, "is_windows_host", lambda: False)
    with pytest.raises((ProductStoreError, ValueError)):
        source.control.import_setup(request)
    assert not any(counts(source.store).values())


def test_two_store_concurrent_exact_import_has_one_immutable_origin(imported_source):
    source = imported_source
    other = ProductStore(source.store.path)

    def save(store):
        return store.import_windows_file_access_setup(
            source.checked, selection=source.selection, now_ms=source.now
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(save, [source.store, other]))
    assert results[0] == results[1]
    assert counts(source.store)["file_access_setup_imports"] == 1


def test_existing_selection_conflict_never_calls_observer(imported_source, monkeypatch):
    source = imported_source
    source.control.import_setup(source.selection)
    monkeypatch.setattr(
        windows_context,
        "read_windows_file_setup_status",
        lambda **_: pytest.fail("conflicting selection"),
    )
    with pytest.raises(ProductStoreError):
        source.control.import_setup({**source.selection, "enrollment_digest": "sha256:" + "0" * 64})
    with source.store._connection(write=True) as connection:
        with pytest.raises(Exception, match="append-only"):
            connection.execute("DELETE FROM file_access_setup_imports")


def test_same_generation_different_enrollment_is_rejected_without_partial_insert(imported_source):
    source = imported_source
    row = deepcopy(source.row)
    row["enrollment_id"] = "win-file-enrollment-" + "c" * 32
    altered = object.__new__(enrollment.VerifiedWindowsSetup)
    object.__setattr__(altered, "_raw", canonical_json_bytes(row))
    object.__setattr__(altered, "_receipt", source.checked._receipt)
    with pytest.raises(ProductStoreError):
        source.store.import_windows_file_access_setup(
            altered,
            selection={
                "enrollment_id": row["enrollment_id"],
                "enrollment_digest": content_hash(row),
            },
            now_ms=source.now,
        )
    assert not any(counts(source.store).values())
    with source.store._connection() as connection:
        assert connection.execute("SELECT count(*) FROM file_access_enrollments").fetchone()[0] == 0


def test_generation_unique_conflict_rolls_back_new_enrollment(imported_source):
    source = imported_source
    # A conflicting legacy/corrupt row must not leave even an enrollment insert.
    with source.store._connection(write=True) as connection:
        connection.execute(
            "INSERT INTO file_access_enrollments VALUES(?,?,?)",
            ("legacy-other", "{}", content_hash({})),
        )
        connection.execute(
            "INSERT INTO file_access_setup_imports VALUES(?,?,?,?,?)",
            ("legacy-control", "legacy-other", source.row["generation"], "{}", content_hash({})),
        )
    with pytest.raises(ProductStoreError):
        source.control.import_setup(source.selection)
    with source.store._connection() as connection:
        assert (
            connection.execute("SELECT enrollment_id FROM file_access_enrollments").fetchall()[0][0]
            == "legacy-other"
        )
        assert connection.execute("SELECT count(*) FROM file_access_enrollments").fetchone()[0] == 1


def test_schema_upgrade_preserves_existing_rows_and_adds_append_only_imports(imported_source):
    source = imported_source
    with source.store._connection(write=True) as connection:
        connection.execute("DROP TABLE file_access_setup_imports")
        connection.execute(
            "INSERT INTO file_access_enrollments VALUES(?,?,?)",
            ("linux-prior", '{"immutable":true}', content_hash({"immutable": True})),
        )
        before = [tuple(row) for row in connection.execute("SELECT * FROM file_access_enrollments")]
    upgraded = ProductStore(source.store.path)
    with upgraded._connection() as connection:
        assert [
            tuple(row) for row in connection.execute("SELECT * FROM file_access_enrollments")
        ] == before
        assert (
            connection.execute("SELECT count(*) FROM file_access_setup_imports").fetchone()[0] == 0
        )
        assert {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='trigger' AND tbl_name='file_access_setup_imports'"
            )
        } == {"file_access_setup_imports_no_update", "file_access_setup_imports_no_delete"}
    assert (
        upgraded.import_windows_file_access_setup(
            source.checked, selection=source.selection, now_ms=source.now
        )["status"]
        == "setup_verified"
    )


@pytest.fixture
def baseline(imported_source):
    source = imported_source
    source.control.import_setup(source.selection)
    saved = source.store.get_windows_file_access_import(source.selection)
    context = admission.baseline_context(saved)
    body = {
        "schema_version": "bluefire.file-access-control-review.v1",
        "operation": "baseline",
        "control_owner_id": saved["control_owner_id"],
        "control_digest": content_hash(saved),
        "context_digest": content_hash(context),
        "enrollment_digest": content_hash(source.row),
        "expires_at_ms": source.now + 10000,
        "effect": "synthetic explicit read review",
    }
    review = {**body, "review_digest": content_hash(body)}
    request = {
        "submission_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        "review": {"operation": "baseline", "control_owner_id": saved["control_owner_id"]},
        "review_digest": review["review_digest"],
        "reviewed_by": "fake-operator",
    }
    job, created = source.store.create_file_access_operation(
        request,
        review_document=review,
        review_context=context,
        enrollment_id=source.row["enrollment_id"],
        now_ms=source.now,
    )
    assert created is True
    original = source.store.file_access_operation_records(job["job_id"])["document"]
    prepared = admission.build_preparation(job["job_id"], original, saved, issued_at_ms=source.now)
    return SimpleNamespace(
        **vars(source),
        saved=saved,
        context=context,
        review=review,
        request=request,
        job=job,
        original=original,
        prepared=prepared,
    )


def test_original_private_preparation_is_saved_once_and_full_pair_lookup_works(baseline):
    source = baseline
    source.store.prepare_file_access_operation(
        source.job["job_id"], source.prepared, now_ms=source.now
    )
    source.store.prepare_file_access_operation(
        source.job["job_id"], deepcopy(source.prepared), now_ms=source.now
    )
    pair = source.prepared["original"]
    assert source.prepared["expires_at_ms"] == source.now + 5000
    assert "reviewed_operation" not in pair["manifest"]
    assert pair["manifest"]["approval"]["approved_by"] == source.request["reviewed_by"]
    calls = []
    source.store.register_file_access_task(
        source.job["job_id"],
        task_id=pair["task_id"],
        step_id="read_generated",
        manifest=pair["manifest"],
        runner_profile=pair["profile"],
        now_ms=source.now,
        validate_context=lambda: calls.append("fresh trusted revalidation"),
    )
    saved = source.store.file_access_task_record(
        pair["task_id"], pair["transport_request_hash"], include_terminal=False
    )
    assert saved["task"]["manifest"] == pair["manifest"]
    assert calls == ["fresh trusted revalidation"]
    assert counts(source.store)["file_access_task_claims"] == 1
    with pytest.raises(FileAccessContractError, match="unsupported operation obligation"):
        source.control.control(source.saved["control_owner_id"])
    with pytest.raises(FileAccessContractError, match="unsupported operation obligation"):
        source.control.import_setup(source.selection)
    with pytest.raises(FileAccessContractError, match="unsupported operation obligation"):
        source.control.controls()
    with pytest.raises(ProductStoreError):
        source.store.finish_file_access_operation(
            source.job["job_id"],
            outcome={"state": "complete", "evidence_digest": content_hash([])},
            control=source.saved,
        )


@pytest.mark.parametrize(
    "change",
    ["extra", "profile", "resource", "actor", "job", "revision", "deadline", "clock", "ordinary"],
)
def test_preparation_rejects_changed_original_authority(baseline, change):
    source = baseline
    prepared = deepcopy(source.prepared)
    now = source.now
    if change == "extra":
        prepared["renew"] = True
    elif change == "profile":
        prepared["original"]["profile"]["allowed_actions"] = ["sandbox.cleanup.v1"]
    elif change == "resource":
        prepared["expected_binding"]["resource"]["file_identity"]["file_id"] = "f" * 32
    elif change == "actor":
        prepared["original"]["manifest"]["approval"]["approved_by"] = "other"
    elif change == "job":
        prepared["job_id"] = "job-" + "b" * 32
    elif change == "revision":
        prepared["expected_binding"]["control_revision"] = 2
    elif change == "deadline":
        now = prepared["expires_at_ms"]
    elif change == "clock":
        now -= 1
    elif change == "ordinary":
        prepared["schema_version"] = "bluefire.file-access-operation-preparation.v1"
    with pytest.raises((ProductStoreError, ValueError, KeyError)):
        source.store.prepare_file_access_operation(source.job["job_id"], prepared, now_ms=now)
    assert source.store.file_access_operation_records(source.job["job_id"])["preparation"] is None


def test_builder_binds_the_submitted_uuid_to_original_job(baseline):
    with pytest.raises(ValueError):
        admission.build_preparation(
            "job-" + "f" * 32, baseline.original, baseline.saved, issued_at_ms=baseline.now
        )


@pytest.mark.parametrize(
    "change", ["duplicate", "expiry", "rollback", "revalidation", "stopped", "pair"]
)
def test_private_registration_never_renews_or_replays(baseline, change):
    source = baseline
    source.store.prepare_file_access_operation(
        source.job["job_id"], source.prepared, now_ms=source.now
    )
    pair = deepcopy(source.prepared["original"])
    now = source.now

    def callback():
        return None

    def register():
        source.store.register_file_access_task(
            source.job["job_id"],
            task_id=pair["task_id"],
            step_id="read_generated",
            manifest=pair["manifest"],
            runner_profile=pair["profile"],
            now_ms=now,
            validate_context=callback,
        )

    if change == "duplicate":
        register()
    elif change == "expiry":
        now = source.prepared["expires_at_ms"]
    elif change == "rollback":
        now -= 1
    elif change == "revalidation":

        def callback():
            raise ProductStoreError("Fresh protected facts changed")

    elif change == "stopped":
        with source.store._connection(write=True) as connection:
            connection.execute(
                "UPDATE jobs SET state='cancelled' WHERE job_id=?", (source.job["job_id"],)
            )
    elif change == "pair":
        pair["profile"]["limits"]["timeout_ms"] = 1
    with pytest.raises((ProductStoreError, ValueError)):
        register()
    assert counts(source.store)["file_access_task_claims"] == (1 if change == "duplicate" else 0)


def test_unsupported_operation_history_refuses_setup_only_view_even_without_tasks(baseline):
    with pytest.raises(FileAccessContractError, match="unsupported operation obligation"):
        baseline.control.control(baseline.saved["control_owner_id"])
    assert counts(baseline.store)["file_access_task_claims"] == 0
    baseline.store.finish_file_access_operation(
        baseline.job["job_id"],
        outcome={"state": "refused_no_effect", "evidence_digest": content_hash([])},
    )
    with pytest.raises(FileAccessContractError, match="unsupported operation obligation"):
        baseline.control.control(baseline.saved["control_owner_id"])


@pytest.mark.parametrize("change", ["none", "control", "usage", "truthy_usage"])
def test_private_task_guards_use_the_same_write_transaction(baseline, monkeypatch, change):
    from bluefire import product_store_file_access as store_module
    from bluefire import product_store_windows_file_access as windows_store

    source = baseline
    source.store.prepare_file_access_operation(
        source.job["job_id"], source.prepared, now_ms=source.now
    )
    control_at, usage = store_module._control_at, store_module._usage_settled
    register = windows_store.register_task
    observations = []
    validated = []

    def current_control(connection, owner):
        assert connection.in_transaction and owner == source.saved["control_owner_id"]
        result = control_at(connection, owner)
        if change == "control":
            result = deepcopy(result)
            result["document"]["revision"] += 1
        observations.append(("control", connection, result["document"]))
        return result

    def current_usage(store, connection, owner):
        assert store is source.store and connection.in_transaction
        result = usage(store, connection, owner) and change != "usage"
        if change == "truthy_usage":
            result = "not a verified boolean"
        observations.append(("usage", connection, result))
        return result

    def register_current(connection, **kwargs):
        assert [row[0] for row in observations] == ["control", "usage"]
        assert all(row[1] is connection for row in observations)
        assert kwargs["control_document"] is observations[0][2]
        assert kwargs["usage_settled"] is observations[1][2]
        register(connection, **kwargs)

    monkeypatch.setattr(store_module, "_control_at", current_control)
    monkeypatch.setattr(store_module, "_usage_settled", current_usage)
    monkeypatch.setattr(windows_store, "register_task", register_current)
    pair = source.prepared["original"]

    def claim():
        source.store.register_file_access_task(
            source.job["job_id"],
            task_id=pair["task_id"],
            step_id="read_generated",
            manifest=pair["manifest"],
            runner_profile=pair["profile"],
            now_ms=source.now,
            validate_context=lambda: validated.append(True),
        )

    if change == "none":
        claim()
        assert validated == [True]
    else:
        with pytest.raises(ValueError):
            claim()
        assert not validated
    assert counts(source.store)["file_access_task_claims"] == (1 if change == "none" else 0)


@pytest.mark.parametrize("operation", ["baseline", "create", "harden", "rollback", "reset"])
def test_public_operations_never_queue_from_imported_provenance(imported_source, operation):
    source = imported_source
    saved = source.control.import_setup(source.selection)
    with pytest.raises((ProductStoreError, ValueError)):
        source.control.review(
            {
                "operation": operation,
                "control_owner_id": None if operation == "create" else saved["control_owner_id"],
            }
        )
    assert counts(source.store)["jobs"] == 0
