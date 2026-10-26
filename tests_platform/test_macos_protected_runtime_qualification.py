from __future__ import annotations

import hashlib
import queue
from pathlib import Path

import pytest

from tools import provision_macos_protected_python as provision
from tools import verify_macos_file_access_lifecycle as lifecycle


def _wheel_row(path: Path) -> dict[str, object]:
    content = path.read_bytes()
    return {"name": path.name, "sha256": hashlib.sha256(content).hexdigest(), "bytes": len(content)}


def test_promotion_binds_each_wheel_to_its_own_manifest_row(tmp_path, monkeypatch):
    staged = tmp_path / "staged"
    protected = tmp_path / "protected"
    staged.mkdir()
    protected.mkdir()
    first = staged / "a_dependency-1-py3-none-any.whl"
    second = staged / "z_dependency-2-py3-none-any.whl"
    first.write_bytes(b"first wheel")
    second.write_bytes(b"a different, longer wheel")
    rows = provision._wheel_rows_by_name([_wheel_row(first), _wheel_row(second)])
    monkeypatch.setattr(provision.os, "chown", lambda *args: None, raising=False)

    provision._promote_wheels([first, second], rows, protected)

    assert (protected / first.name).read_bytes() == first.read_bytes()
    assert (protected / second.name).read_bytes() == second.read_bytes()


def test_promotion_rejects_bytes_that_do_not_match_that_wheels_row(tmp_path, monkeypatch):
    staged = tmp_path / "staged"
    protected = tmp_path / "protected"
    staged.mkdir()
    protected.mkdir()
    first = staged / "a_dependency-1-py3-none-any.whl"
    second = staged / "z_dependency-2-py3-none-any.whl"
    first.write_bytes(b"first wheel")
    second.write_bytes(b"a different, longer wheel")
    rows = provision._wheel_rows_by_name([_wheel_row(first), _wheel_row(second)])
    rows[first.name] = {**rows[first.name], "sha256": "0" * 64}
    monkeypatch.setattr(provision.os, "chown", lambda *args: None, raising=False)

    with pytest.raises(ValueError, match="changed during protected promotion"):
        provision._promote_wheels([first, second], rows, protected)


def test_dyld_shared_cache_system_install_name_needs_no_filesystem_entry():
    assert provision._is_sip_system_path("/usr/lib/libSystem.B.dylib")
    assert provision._is_sip_system_path(
        "/System/Library/Frameworks/Foundation.framework/Versions/A/Foundation"
    )
    assert not provision._is_sip_system_path("/usr/lib/../tmp/attacker.dylib")
    assert not provision._is_sip_system_path("/opt/homebrew/lib/libexample.dylib")


def test_rpath_candidate_selection_does_not_skip_an_earlier_existing_path(tmp_path):
    loader = tmp_path / "runtime" / "lib" / "python.dylib"
    executable = tmp_path / "runtime" / "bin"
    unsafe = tmp_path / "unprotected"
    later_safe = tmp_path / "runtime" / "lib"
    loader.parent.mkdir(parents=True)
    executable.mkdir(parents=True)
    unsafe.mkdir()
    later_safe.mkdir(parents=True, exist_ok=True)
    (unsafe / "libexample.dylib").write_bytes(b"unprotected")
    (later_safe / "libexample.dylib").write_bytes(b"protected")

    selected = provision._first_rpath_candidate(
        [str(unsafe), str(later_safe)], "libexample.dylib", loader, executable
    )

    assert selected == (unsafe / "libexample.dylib").resolve()
    assert not provision._is_sip_system_path(selected.as_posix())


def test_missing_system_looking_rpath_does_not_mask_later_unprotected_candidate(tmp_path):
    loader = tmp_path / "runtime" / "lib" / "python.dylib"
    executable = tmp_path / "runtime" / "bin"
    unsafe = tmp_path / "unprotected"
    loader.parent.mkdir(parents=True)
    executable.mkdir(parents=True)
    unsafe.mkdir()
    (unsafe / "libexample.dylib").write_bytes(b"unprotected")

    selected = provision._first_rpath_candidate(
        ["/usr/lib/does-not-exist", str(unsafe)], "libexample.dylib", loader, executable
    )

    assert selected == (unsafe / "libexample.dylib").resolve()
    assert not provision._is_sip_system_path(selected.as_posix())


def test_otool_parsers_capture_rpaths_and_skip_architecture_headers():
    load_commands = """Load command 2
      cmd LC_RPATH
  cmdsize 48
     path @loader_path/../lib (offset 12)
Load command 3
      cmd LC_RPATH
  cmdsize 40
     path @executable_path/../lib (offset 12)
"""
    dependencies = """python3.11:
    @rpath/libcrypto.3.dylib (compatibility version 3.0.0, current version 3.0.0)
    /usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1351.0.0)
python3.11 (architecture arm64):
    @rpath/libcrypto.3.dylib (compatibility version 3.0.0, current version 3.0.0)
"""

    assert provision._parse_lc_rpaths(load_commands) == [
        "@loader_path/../lib",
        "@executable_path/../lib",
    ]
    assert provision._parse_otool_dependencies(dependencies) == [
        "@rpath/libcrypto.3.dylib",
        "/usr/lib/libSystem.B.dylib",
        "@rpath/libcrypto.3.dylib",
    ]


def test_link_diagnostic_is_bounded_and_redacts_external_parent_paths(tmp_path):
    prefix = tmp_path / "protected"
    external = tmp_path / "runner-private" / "libunexpected.dylib"
    image = prefix / "cpython" / "bin" / "python3.11"
    external.parent.mkdir()
    external.write_bytes(b"untrusted")

    diagnostic = provision._link_diagnostic(
        image,
        "@rpath/libunexpected.dylib",
        "outside_prefix_and_sip",
        prefix,
        candidate=external,
        rpath_candidates=[
            {
                "index": 0,
                "origin": "absolute",
                "candidate": "external/libunexpected.dylib",
                "exists": True,
            }
        ],
    )
    error = provision.DynamicLinkAuditError([diagnostic], truncated=False)
    receipt = provision._failure_document(error)

    assert diagnostic["image"] == "python3.11"
    assert diagnostic["dependency"] == "@rpath/libunexpected.dylib"
    assert diagnostic["candidate"] == "external/libunexpected.dylib"
    assert "runner-private" not in repr(diagnostic)
    assert receipt["error_type"] == "DynamicLinkAuditError"
    assert receipt["dynamic_link_diagnostics"] == {
        "schema_version": "bluefire.macos-dynamic-link-diagnostic.v1",
        "violations": [diagnostic],
        "truncated": False,
    }


def test_link_diagnostic_receipt_caps_violation_and_rpath_lists():
    prefix = Path("/private/var/db/bluefire-macos-runtime/1-1")
    image = prefix / "cpython" / "bin" / "python3.11"
    rpaths = [
        {
            "index": index,
            "origin": "absolute",
            "candidate": f"missing/lib{index}.dylib",
            "exists": False,
        }
        for index in range(provision.MAX_RPATH_CANDIDATES + 3)
    ]
    violations = [
        provision._link_diagnostic(
            image,
            "@rpath/libbad.dylib",
            "unresolved_dependency",
            prefix,
            rpath_candidates=rpaths,
        )
        for _ in range(provision.MAX_LINK_DIAGNOSTICS + 1)
    ]

    error = provision.DynamicLinkAuditError(violations, truncated=True)
    failure = provision._failure_document(error)
    diagnostics = failure["dynamic_link_diagnostics"]

    assert len(diagnostics["violations"]) == provision.MAX_LINK_DIAGNOSTICS
    assert diagnostics["truncated"] is True
    assert len(diagnostics["violations"][0]["rpath_candidates"]) == provision.MAX_RPATH_CANDIDATES
    assert diagnostics["violations"][0]["rpath_candidates_limit_reached"] is True


class _FakeProcess:
    pid = 1234
    returncode = None
    stdout = None
    stderr = None

    def __init__(self):
        self.wait_calls = 0

    def wait(self, timeout=None):
        self.wait_calls += 1
        self.returncode = 0
        return self.returncode


class _Reader:
    def __init__(self, alive=False):
        self.alive = alive

    def join(self, timeout=None):
        return None

    def is_alive(self):
        return self.alive


class _UnclosableStream:
    def close(self):
        raise AssertionError("cleanup must not block on a reader-owned TextIOWrapper")


def test_group_wait_keeps_original_child_unreaped_until_group_is_empty(monkeypatch):
    process = _FakeProcess()
    monkeypatch.setattr(lifecycle, "_child_exit_state", lambda _pid: True)
    live = iter([True, False])

    def group_live(_group):
        result = next(live)
        assert process.wait_calls == 0
        return result

    monkeypatch.setattr(lifecycle, "_group_has_live_members", group_live)

    assert lifecycle._wait_owned_group(process, timeout=1)
    assert process.wait_calls == 1
    assert process.returncode == 0


def test_escalation_signals_only_while_original_child_still_pins_group(monkeypatch):
    process = _FakeProcess()
    handle = lifecycle.SupervisorHandle(
        process, queue.Queue(), queue.Queue(), (_Reader(), _Reader())
    )
    wait_results = iter([False, False, False])
    monkeypatch.setattr(
        lifecycle, "_wait_owned_group", lambda *_args, **_kwargs: next(wait_results)
    )
    monkeypatch.setattr(lifecycle, "_child_exit_state", lambda _pid: False)
    monkeypatch.setattr(lifecycle.signal, "SIGKILL", 9, raising=False)
    signals = []

    def signal_group(group_id, sig):
        assert group_id == process.pid
        assert process.wait_calls == 0
        signals.append(sig)

    monkeypatch.setattr(lifecycle.os, "kill", lambda pid, sig: signals.append((pid, sig)))
    monkeypatch.setattr(lifecycle.os, "killpg", signal_group, raising=False)

    result = lifecycle._stop_supervisor(handle)

    assert signals == [
        (process.pid, lifecycle.signal.SIGTERM),
        lifecycle.signal.SIGTERM,
        lifecycle.signal.SIGKILL,
    ]
    assert result["process_group_gone"] is False
    assert result["drained"] is False
    assert process.wait_calls == 0


def test_undrained_reader_is_not_closed_from_another_thread(monkeypatch):
    process = _FakeProcess()
    process.stdout = _UnclosableStream()
    process.stderr = _UnclosableStream()
    handle = lifecycle.SupervisorHandle(
        process, queue.Queue(), queue.Queue(), (_Reader(alive=True), _Reader(alive=True))
    )
    monkeypatch.setattr(lifecycle.os, "kill", lambda *_args: None)
    monkeypatch.setattr(lifecycle, "_child_exit_state", lambda _pid: False)
    monkeypatch.setattr(
        lifecycle,
        "_wait_owned_group",
        lambda *_args, **_kwargs: setattr(process, "returncode", 0) or True,
    )

    result = lifecycle._stop_supervisor(handle)

    assert result["streams_drained"] is False
    assert result["drained"] is False
