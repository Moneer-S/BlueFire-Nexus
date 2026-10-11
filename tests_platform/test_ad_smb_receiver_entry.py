"""Fake installed constructor/lifecycle; no listener, credentials or AD calls."""

import threading
from contextlib import nullcontext
from datetime import datetime, timedelta
from types import SimpleNamespace

import pytest

from bluefire import ad_smb_receiver_entry as entry
from bluefire.ad_smb_contract import AdSmbError, AdSmbScope
from bluefire.util import canonical_json_bytes
from tests_platform.test_ad_smb_contract import NOW
from tests_platform.test_ad_smb_receiver import original


@pytest.fixture
def setup(tmp_path, monkeypatch):
    task, channel = original()
    scope = AdSmbScope.from_mapping(task["manifest"]["params"]["ad_smb_request"]["scope"])
    calls = []
    stop = threading.Event()
    state = SimpleNamespace(
        start_failure=False, shutdown_failure=False, unknown=False, expired=False
    )

    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return NOW + timedelta(seconds=172800 if state.expired else 2)

    class Receiver:
        def __init__(self, *a, **kw):
            calls.append("construct")
            assert kw["credential_root"] is None and kw["credential_binding_digest"] is None
            self._stop = threading.Event()
            self._workers_lock = threading.Lock()
            self._workers = set()
            self._listener = SimpleNamespace(fileno=lambda: -1 if not state.unknown else 123)
            self._ledger_lock = None
            self._serve_thread = None

        def start(self):
            calls.append("start")
            if state.start_failure:
                raise RuntimeError("synthetic start failure")
            stop.set()

        def shutdown(self):
            calls.append("shutdown")
            if state.shutdown_failure:
                raise RuntimeError("synthetic cleanup failure")

    row = {
        "runner_binary": str(tmp_path / "not-executed.exe"),
        "profile": task["profile"],
        "credential_binding_digest": None,
    }
    monkeypatch.setattr(entry.sys, "platform", "win32")
    monkeypatch.setattr(entry, "datetime", Clock)
    monkeypatch.setattr(entry, "managed_product_root", lambda: tmp_path)
    monkeypatch.setattr(entry, "_configuration", lambda root: (row, scope, channel))
    monkeypatch.setattr(entry, "private_root", lambda root: tmp_path)
    monkeypatch.setattr(entry, "_PinnedDirectory", lambda *a, **k: nullcontext())
    monkeypatch.setattr(
        entry, "SubprocessRustRunner", lambda *a, **k: calls.append("runner") or object()
    )
    monkeypatch.setattr(entry, "AdmittedAdSmbReceiver", Receiver)
    return stop, calls, state


def test_serve_exact_installed_receiver_and_verify_owned_cleanup(setup):
    stop, calls, _ = setup
    entry.serve_installed(stop)
    assert calls == ["runner", "construct", "start", "shutdown"]


@pytest.mark.parametrize("flag", ["start_failure", "shutdown_failure", "unknown"])
def test_failure_never_certifies_owned_cleanup(setup, flag):
    stop, calls, state = setup
    setattr(state, flag, True)
    with pytest.raises((AdSmbError, RuntimeError)):
        entry.serve_installed(stop)
    assert calls[-1] == "shutdown"


def test_already_cancelled_never_constructs(setup):
    stop, calls, _ = setup
    stop.set()
    entry.serve_installed(stop)
    assert calls == []


def test_expired_original_configuration_never_constructs(setup):
    stop, calls, state = setup
    state.expired = True
    with pytest.raises(AdSmbError):
        entry.serve_installed(stop)
    assert calls == []


@pytest.mark.parametrize("mutation", [None, "extra", "credential", "binary", "profile"])
def test_receiver_configuration_is_closed_and_role_specific(tmp_path, monkeypatch, mutation):
    task, channel = original()
    scope = AdSmbScope.from_mapping(task["manifest"]["params"]["ad_smb_request"]["scope"])
    row = {
        "schema_version": "bluefire.ad-smb-receiver-config.v1",
        "scope": scope.to_dict(),
        "channel": channel.to_dict(),
        "profile": task["profile"],
        "runner_binary": str(tmp_path / "fixed.exe"),
        "credential_binding_digest": None,
    }
    if mutation == "extra":
        row["password"] = "synthetic forbidden value"
    elif mutation == "credential":
        row["credential_binding_digest"] = "sha256:" + "f" * 64
    elif mutation == "binary":
        row["runner_binary"] = "relative.exe"
    elif mutation == "profile":
        row["profile"]["allowed_actions"].append("other")

    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return NOW + timedelta(seconds=2)

    class Pinned:
        def __init__(self, root, *, private, verify_permissions_only):
            assert root == tmp_path and private and verify_permissions_only

        def __enter__(self):
            return self

        def __exit__(self, *_):
            pass

        def names(self, *, maximum):
            assert maximum == 10
            return ["receiver.json"]

        def read(self, name, *, maximum):
            assert name == "receiver.json" and maximum == 131072
            return canonical_json_bytes(row)

    monkeypatch.setattr(entry, "datetime", Clock)
    monkeypatch.setattr(entry, "private_root", lambda root: root)
    monkeypatch.setattr(entry, "_PinnedDirectory", Pinned)
    if mutation is None:
        parsed, actual_scope, actual_channel = entry._configuration(tmp_path)
        assert (
            parsed == row
            and actual_scope.digest == scope.digest
            and actual_channel.digest == channel.digest
        )
    else:
        with pytest.raises(AdSmbError) as error:
            entry._configuration(tmp_path)
        assert "synthetic forbidden value" not in str(error.value)
