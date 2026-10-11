"""CLI routing and real local storage; Linux/runtime admission is synthetic here."""

from __future__ import annotations

import io
import json
import os
from dataclasses import replace
from functools import partial
from types import SimpleNamespace

import pytest

from bluefire import cli
from bluefire import s3_access_setup as setup
from bluefire import s3_access_setup_cli as command
from bluefire.runner_private_files import _PinnedPrivateDirectory
from bluefire.runner_trust import load_local_enrollment
from bluefire.s3_access_contract import S3AccessError
from bluefire.s3_access_extension_store import S3ExtensionStore
from bluefire.util import canonical_json_bytes, content_hash
from tests_platform.test_s3_access_extension import local as local
from tests_platform.test_s3_access_onboarding import configured as configured
from tests_platform.test_s3_access_wire import NOW, credential_row


def portable_input_stat(descriptor):
    value = os.fstat(descriptor)
    # Windows fstat ctime can mean change time while lstat reports creation time.
    # This test-only shim is not proof of POSIX no-follow or timestamp-race checks.
    return SimpleNamespace(
        **{
            name: getattr(value, name)
            for name in ("st_dev", "st_ino", "st_mode", "st_nlink", "st_size", "st_mtime_ns")
        },
        st_ctime_ns=getattr(value, "st_birthtime_ns", value.st_ctime_ns),
    )


def test_portable_stat_keeps_all_non_ctime_identity_fields(tmp_path):
    path = tmp_path / "portable.json"
    path.write_bytes(b"{}")
    with path.open("rb") as stream:
        raw = os.fstat(stream.fileno())
        adapted = portable_input_stat(stream.fileno())
    assert vars(adapted) == {
        **{
            name: getattr(raw, name)
            for name in ("st_dev", "st_ino", "st_mode", "st_nlink", "st_size", "st_mtime_ns")
        },
        "st_ctime_ns": getattr(raw, "st_birthtime_ns", raw.st_ctime_ns),
    }


@pytest.fixture
def owner(local, monkeypatch, tmp_path):
    enrollment, configuration, provider = local
    profile = configuration["environments"][0]["profile"]["profile_id"]
    monkeypatch.setattr(command, "_require_owned_linux", lambda: None)
    monkeypatch.setattr(command, "managed_product_root", lambda: enrollment.root.parent)

    def load(root, **kwargs):
        assert root == enrollment.root and kwargs == {"verify_permissions_only": True}
        return load_local_enrollment(root, secret_provider=provider, **kwargs)

    monkeypatch.setattr(command, "load_local_enrollment", load)
    # Portable input-contract test, not proof of POSIX no-follow handling.
    if os.name == "nt":
        monkeypatch.setattr(
            command,
            "os",
            SimpleNamespace(
                open=os.open,
                close=os.close,
                fstat=portable_input_stat,
                fdopen=os.fdopen,
                O_RDONLY=os.O_RDONLY,
                O_NOFOLLOW=0,
                O_NONBLOCK=0,
            ),
        )
    for name in (
        "review_configuration",
        "apply_configuration",
        "import_temporary_material",
        "inspect_extension",
    ):
        monkeypatch.setattr(setup, name, partial(getattr(setup, name), clock=lambda: NOW))
    monkeypatch.setattr(
        cli,
        "_service",
        lambda *_args, **_kwargs: pytest.fail("S3 setup must not start the product service"),
    )
    draft = tmp_path / "draft.json"
    draft.write_bytes(canonical_json_bytes(configuration))
    return SimpleNamespace(
        enrollment=enrollment,
        configuration=configuration,
        provider=provider,
        profile=profile,
        draft=draft,
        review=tmp_path / "review.json",
    )


def args(owner, *values):
    return cli._parser().parse_args(["s3", *values, "--profile", owner.profile])


def apply(owner):
    reviewed = cli._execute(args(owner, "configure", "review", "--draft", str(owner.draft)))
    owner.review.write_bytes(canonical_json_bytes(reviewed))
    return cli._execute(
        args(
            owner, "configure", "apply", "--draft", str(owner.draft), "--review", str(owner.review)
        )
    )


def test_owner_review_apply_status_and_reconciliation_are_local_and_non_replaying(owner):
    root = S3ExtensionStore(owner.enrollment).root
    status = cli._execute(args(owner, "status"))
    assert status["status"] == "not_configured" and not root.exists()
    assert status["readiness_scope"] == "local_reference_metadata_only"
    configured = apply(owner)
    assert configured["status"] == "configured"
    again = apply(owner)
    assert again["status"] == "already_configured"
    assert again["revision_digest"] == configured["revision_digest"]
    reconciled = cli._execute(
        args(owner, "reconcile", "--record-digest", configured["revision_digest"])
    )
    assert reconciled == {"status": "committed", "matches": True}
    assert S3ExtensionStore(owner.enrollment).read()["sequence"] == 1
    assert (
        load_local_enrollment(owner.enrollment.root, secret_provider=owner.provider).metadata
        == owner.enrollment.metadata
    )


def test_browser_structural_review_cannot_authorize_local_installation(owner, configured):
    from bluefire.s3_access_onboarding import review_draft

    selected = configured.profile
    selected.id = owner.profile
    selected.budgets = replace(selected.budgets, max_seconds=120)
    owner.configuration["schema_version"] = "bluefire.s3-host-environments.v3"
    owner.configuration["environments"][0]["managed_profile_digest"] = content_hash(
        selected.to_dict()
    )
    owner.draft.write_bytes(canonical_json_bytes(owner.configuration))
    reviewed = review_draft(
        configured.service,
        {
            "profile_id": owner.profile,
            "profile_digest": content_hash(selected.to_dict()),
            "configuration_json": owner.draft.read_text(encoding="utf-8"),
        },
    )
    assert reviewed["validation_scope"] == "structural_only"
    owner.review.write_bytes(canonical_json_bytes(reviewed))
    root = S3ExtensionStore(owner.enrollment).root
    assert not root.exists()
    with pytest.raises(S3AccessError):
        cli._execute(
            args(
                owner,
                "configure",
                "apply",
                "--draft",
                str(owner.draft),
                "--review",
                str(owner.review),
            )
        )
    assert not root.exists() and configured.calls == []
    assert apply(owner)["status"] == "configured"


def test_explicit_stdin_import_never_returns_values_or_renews_authority(owner, monkeypatch):
    configured = apply(owner)
    raw = canonical_json_bytes(credential_row())
    monkeypatch.setattr(
        command.sys, "stdin", SimpleNamespace(isatty=lambda: False, buffer=io.BytesIO(raw))
    )
    imported = cli._execute(
        args(
            owner,
            "credentials",
            "set",
            "--environment",
            "test-environment",
            "--expected-revision",
            configured["revision_digest"],
            "--stdin",
        )
    )
    status = cli._execute(args(owner, "status"))
    assert imported["status"] == "reference_imported"
    assert status["references"][0]["state"] == "current"
    for key in ("access_key", "secret_key", "token"):
        assert credential_row()[key] not in json.dumps([imported, status])
    current = S3ExtensionStore(owner.enrollment).read()
    assert current["configuration"] == owner.configuration and current["sequence"] == 2


def test_reconcile_discovers_lost_response_metadata_without_mutation(owner, monkeypatch):
    store = S3ExtensionStore(owner.enrollment)
    absent = cli._execute(args(owner, "reconcile"))
    assert absent == {
        "status": "not_found",
        "record_digest": None,
        "operation": None,
        "sequence": None,
    }
    assert not store.root.exists()
    configured = apply(owner)
    committed = cli._execute(args(owner, "reconcile"))
    assert committed == {
        "status": "committed",
        "record_digest": configured["revision_digest"],
        "operation": "configure",
        "sequence": 1,
    }
    original = _PinnedPrivateDirectory.promote

    def fail(directory, source, destination, **kwargs):
        if source == ".pending.json":
            raise OSError("injected lost publication")
        return original(directory, source, destination, **kwargs)

    monkeypatch.setattr(_PinnedPrivateDirectory, "promote", fail)
    monkeypatch.setattr(
        command.sys,
        "stdin",
        SimpleNamespace(
            isatty=lambda: False, buffer=io.BytesIO(canonical_json_bytes(credential_row()))
        ),
    )
    with pytest.raises(S3AccessError):
        cli._execute(
            args(
                owner,
                "credentials",
                "set",
                "--environment",
                "test-environment",
                "--expected-revision",
                configured["revision_digest"],
                "--stdin",
            )
        )
    before = {path.name: path.read_bytes() for path in store.root.iterdir()}
    original_unprotect = owner.provider.unprotect

    def unprotect(purpose, protected):
        assert not purpose.startswith(
            "bluefire.s3-temporary.v1:"
        ), "must not decrypt cloud material"
        return original_unprotect(purpose, protected)

    monkeypatch.setattr(owner.provider, "unprotect", unprotect)
    pending = json.loads(before[".pending.json"])
    result = cli._execute(args(owner, "reconcile"))
    assert result == {
        "status": "incomplete",
        "record_digest": content_hash(pending),
        "operation": "credentials",
        "sequence": 2,
    }
    assert cli._execute(args(owner, "reconcile", "--record-digest", result["record_digest"])) == {
        "status": "incomplete",
        "matches": True,
    }
    for key in ("access_key", "secret_key", "token"):
        assert credential_row()[key] not in json.dumps(result)
    assert before == {path.name: path.read_bytes() for path in store.root.iterdir()}

    with pytest.raises(S3AccessError):
        cli._execute(args(owner, "reconcile", "--complete"))
    assert before == {path.name: path.read_bytes() for path in store.root.iterdir()}
    monkeypatch.setattr(_PinnedPrivateDirectory, "promote", original)
    completed = cli._execute(
        args(owner, "reconcile", "--record-digest", result["record_digest"], "--complete")
    )
    assert completed == {"status": "committed", "revision_digest": result["record_digest"]}
    assert store.read() == pending
    assert cli._execute(
        args(owner, "reconcile", "--record-digest", result["record_digest"], "--complete")
    ) == {"status": "already_committed", "revision_digest": result["record_digest"]}


@pytest.mark.parametrize("mutation", ["profile", "draft", "review", "oversized", "duplicate"])
def test_bad_configuration_refuses_without_publication_or_input_echo(owner, mutation, capsys):
    reviewed = cli._execute(args(owner, "configure", "review", "--draft", str(owner.draft)))
    if mutation == "review":
        reviewed["configuration_digest"] = "sha256:" + "e" * 64
    owner.review.write_bytes(canonical_json_bytes(reviewed))
    if mutation == "profile":
        owner.profile = "not-enrolled"
    elif mutation == "draft":
        owner.draft.write_bytes(b"PRIVATE INPUT MUST NOT ECHO")
    elif mutation == "oversized":
        owner.draft.write_bytes(b"x" * (512 * 1024 + 1))
    elif mutation == "duplicate":
        owner.draft.write_bytes(b'{"environments":[],"environments":[]}')
    result = cli.main(
        [
            "s3",
            "configure",
            "apply",
            "--profile",
            owner.profile,
            "--draft",
            str(owner.draft),
            "--review",
            str(owner.review),
        ]
    )
    assert result == 2
    output = capsys.readouterr()
    assert "PRIVATE INPUT" not in output.out and str(owner.draft) not in output.out
    assert not output.err
    assert not S3ExtensionStore(owner.enrollment).root.exists()


@pytest.mark.parametrize("kind", ["tty", "oversized", "stale", "environment", "invalid"])
def test_credential_failures_neither_echo_nor_publish(owner, monkeypatch, kind, capsys):
    configured = apply(owner)
    store = S3ExtensionStore(owner.enrollment)
    before = {path.name: path.read_bytes() for path in store.root.iterdir()}
    raw = canonical_json_bytes(credential_row())
    if kind == "oversized":
        raw = b"x" * (16 * 1024 + 1)
    elif kind == "invalid":
        raw = b"PRIVATE INPUT MUST NOT ECHO"
    monkeypatch.setattr(
        command.sys, "stdin", SimpleNamespace(isatty=lambda: kind == "tty", buffer=io.BytesIO(raw))
    )
    result = cli.main(
        [
            "s3",
            "credentials",
            "set",
            "--profile",
            owner.profile,
            "--stdin",
            "--environment",
            "other" if kind == "environment" else "test-environment",
            "--expected-revision",
            "sha256:" + "0" * 64 if kind == "stale" else configured["revision_digest"],
        ]
    )
    assert result == 2
    output = capsys.readouterr()
    assert "PRIVATE INPUT" not in output.out
    assert credential_row()["secret_key"] not in output.out
    assert before == {path.name: path.read_bytes() for path in store.root.iterdir()}


def test_real_unsupported_host_refuses_before_filesystem_or_service(monkeypatch):
    if command.sys.platform.startswith("linux") and getattr(os, "getuid", lambda: 0)() > 0:
        pytest.skip("requires unsupported host")
    monkeypatch.setattr(
        command,
        "load_local_enrollment",
        lambda *_a, **_k: pytest.fail("host gate must precede filesystem access"),
    )
    with pytest.raises(S3AccessError):
        command.execute(cli._parser().parse_args(["s3", "status", "--profile", "test"]))


def test_no_secret_argument_or_implicit_stdin_is_registered():
    with pytest.raises(SystemExit):
        cli._parser().parse_args(
            [
                "s3",
                "credentials",
                "set",
                "--profile",
                "test",
                "--environment",
                "test",
                "--expected-revision",
                "sha256:" + "0" * 64,
            ]
        )


@pytest.mark.parametrize("name", ["O_NOFOLLOW", "O_NONBLOCK"])
def test_missing_platform_flag_refuses_before_open(tmp_path, monkeypatch, name):
    values = {"O_RDONLY": 0, "O_NOFOLLOW": 1, "O_NONBLOCK": 2}
    values.pop(name)
    monkeypatch.setattr(
        command,
        "os",
        SimpleNamespace(
            **values, open=lambda *_args: pytest.fail("Missing safety flag must refuse before open")
        ),
    )
    with pytest.raises(S3AccessError):
        command._document(tmp_path / "draft.json", 1024)
