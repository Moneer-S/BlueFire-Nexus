"""Fixed entry argument/environment and process identity tests; no SDK startup."""

from __future__ import annotations

import io
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest

from bluefire import s3_access_worker_entry as entry


def test_entry_refuses_nonisolated_start_after_clearing_environment(monkeypatch):
    environ = {"AWS_PROFILE": "untrusted", "BOTO_CONFIG": "private", "PYTHONPATH": "outside"}
    monkeypatch.setattr(entry, "os", SimpleNamespace(environ=environ))
    monkeypatch.setattr(
        entry,
        "sys",
        SimpleNamespace(
            platform="linux",
            flags=SimpleNamespace(isolated=0, no_site=0),
            dont_write_bytecode=False,
        ),
    )
    assert entry.main([]) == 2 and environ == {}


@pytest.mark.parametrize(
    "args",
    [
        [],
        ["--help"],
        ["--factory", "other"],
        ["--runtime-root", "/owned", "--runtime-digest", "digest", "--extra"],
        ["--runtime-digest", "digest", "--runtime-root", "/owned"],
    ],
)
def test_no_extra_factory_command_or_argument_channel(monkeypatch, capsys, args):
    monkeypatch.setattr(entry, "os", SimpleNamespace(environ={}))
    monkeypatch.setattr(
        entry,
        "sys",
        SimpleNamespace(
            platform="linux", flags=SimpleNamespace(isolated=1, no_site=1), dont_write_bytecode=True
        ),
    )
    assert entry.main(args) == 2
    assert capsys.readouterr() == ("", "")


def stat_payload(start="123", pid=42):
    fields = ["R"] + ["0"] * 18 + [start] + ["0"] * 3
    return f"{pid} (name with ) parentheses) ".encode() + " ".join(fields).encode()


def test_process_creation_identity_uses_exact_self_pid_and_start_ticks(monkeypatch):
    requested = []

    def path(name):
        requested.append(name)
        return SimpleNamespace(open=lambda mode: io.BytesIO(stat_payload()))

    monkeypatch.setattr(entry, "Path", path)
    monkeypatch.setattr(entry.os, "getpid", lambda: 42)
    assert entry._identity() == (42, "123")
    assert requested == ["/proc/self/stat"]


@pytest.mark.parametrize(
    "raw",
    [
        stat_payload(pid=43),
        stat_payload(start="0"),
        stat_payload(start="-1"),
        stat_payload(start="0" + "1" * 32),
        b"x" * 4097,
    ],
)
def test_changed_or_unbounded_process_identity_refused(monkeypatch, raw):
    monkeypatch.setattr(
        entry, "Path", lambda name: SimpleNamespace(open=lambda mode: io.BytesIO(raw))
    )
    monkeypatch.setattr(entry.os, "getpid", lambda: 42)
    with pytest.raises(ValueError):
        entry._identity()


def test_entry_binds_factory_process_and_expected_pins_before_worker(monkeypatch):
    calls = []
    environ = {
        "AWS_PROFILE": "ignored",
        "AWS_DATA_PATH": "ignored",
        "BOTOCORE_EXPERIMENTAL__PLUGINS": "ignored",
    }
    fake_sys = SimpleNamespace(
        platform="linux",
        flags=SimpleNamespace(isolated=1, no_site=1),
        dont_write_bytecode=True,
        modules={},
        stdin=SimpleNamespace(buffer=io.BytesIO()),
        stdout=SimpleNamespace(buffer=io.BytesIO()),
    )
    monkeypatch.setattr(entry, "sys", fake_sys)
    monkeypatch.setattr(
        entry,
        "os",
        SimpleNamespace(environ=environ, fstat=lambda fd: SimpleNamespace(st_mode=stat.S_IFIFO)),
    )
    root = Path(entry.__file__).parent
    verified = SimpleNamespace(
        worker_root=root,
        runtime_digest="sha256:" + "a" * 64,
        worker_generation="sha256:" + "b" * 64,
        create_factory=lambda: calls.append("factory") or "verified-factory",
    )

    def validate(path, digest):
        assert not environ and path == Path("/owned") and digest == verified.runtime_digest
        calls.append("validated")
        return verified

    def execute(module):
        module.validate_runtime = validate

    def worker(source, destination, **kwargs):
        calls.append("worker")
        assert kwargs["factory"] == "verified-factory"
        assert kwargs["process_id"] == 42 and kwargs["creation_identity"] == "123"
        assert kwargs["nonce"] == "c" * 64
        assert kwargs["expected_runtime_digest"] == verified.runtime_digest
        assert kwargs["expected_worker_generation"] == verified.worker_generation
        assert kwargs["clock"]().utcoffset().total_seconds() == 0
        return 0

    spec = SimpleNamespace(
        name="bluefire.s3_access_runtime", loader=SimpleNamespace(exec_module=execute)
    )
    monkeypatch.setattr(
        entry,
        "importlib",
        SimpleNamespace(
            util=SimpleNamespace(
                spec_from_file_location=lambda *a: spec,
                module_from_spec=lambda spec: SimpleNamespace(),
            ),
            import_module=lambda name: SimpleNamespace(run_worker=worker),
        ),
    )
    monkeypatch.setattr(entry, "_identity", lambda: (42, "123"))
    monkeypatch.setattr(entry.secrets, "token_hex", lambda count: "c" * 64)
    assert (
        entry.main(["--runtime-root", "/owned", "--runtime-digest", verified.runtime_digest]) == 0
    )
    assert calls == ["validated", "factory", "worker"]
    assert fake_sys.modules["bluefire"].__path__ == [str(root)]
