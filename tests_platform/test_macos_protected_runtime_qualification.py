from __future__ import annotations

import hashlib
import io
import json
import os
import queue
import subprocess
import sys
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace

import pytest

from bluefire import cli
from bluefire import macos_file_access_local as local
from tools import provision_macos_protected_python as provision
from tools import verify_macos_file_access_lifecycle as lifecycle


def test_lifecycle_supervisor_invokes_the_executable_cli_module(tmp_path):
    python = tmp_path / "protected" / "bin" / "python"
    argv = lifecycle._supervisor_argv(python)

    assert argv == [
        str(python),
        "-I",
        "-B",
        "-m",
        "bluefire.cli",
        "runner",
        "macos-file-setup",
        "--confirm-create-generated-workspace",
        "--port",
        "0",
        "--no-browser",
    ]
    help_result = subprocess.run(
        [sys.executable, "-B", "-m", "bluefire.cli", "--help"],
        capture_output=True,
        check=False,
        timeout=10,
        text=True,
    )
    assert help_result.returncode == 0
    assert "usage:" in help_result.stdout.lower()


def _wheel_row(path: Path) -> dict[str, object]:
    content = path.read_bytes()
    return {"name": path.name, "sha256": hashlib.sha256(content).hexdigest(), "bytes": len(content)}


def test_protected_python_installs_into_pip_free_runtime_with_offline_tooling(tmp_path):
    interpreter = tmp_path / "cpython" / "bin" / "python3.11"
    installer = tmp_path / "installer-venv"
    runtime = tmp_path / "venv"
    wheelhouse = tmp_path / "wheelhouse"
    wheel = wheelhouse / "bluefire_nexus-3.0.0rc2-py3-none-any.whl"

    assert provision._cpython_configure_command(tmp_path / "python", tmp_path / "openssl") == [
        "./configure",
        f"--prefix={tmp_path / 'python'}",
        f"--with-openssl={tmp_path / 'openssl'}",
        "--with-openssl-rpath=no",
        "--with-ensurepip=no",
        "--disable-test-modules",
    ]
    assert provision._venv_command(interpreter, runtime, without_pip=True) == [
        str(interpreter),
        "-m",
        "venv",
        "--without-pip",
        str(runtime),
    ]
    assert provision._venv_command(interpreter, installer, without_pip=False) == [
        str(interpreter),
        "-m",
        "venv",
        str(installer),
    ]

    command = provision._offline_install_command(
        installer / "bin" / "python",
        runtime / "bin" / "python",
        wheelhouse,
        wheel,
    )
    assert command[:4] == [str(installer / "bin" / "python"), "-m", "pip", "--python"]
    assert command[4] == str(runtime / "bin" / "python")
    assert command[5:7] == ["install", "--no-index"]
    assert "--only-binary=:all:" in command
    assert "--no-compile" in command
    assert str(wheelhouse) in command
    assert command[-1] == str(wheel)
    assert str(runtime) not in command[:4]


def test_offline_installer_is_removed_after_success_and_failure(tmp_path, monkeypatch):
    interpreter = tmp_path / "cpython" / "bin" / "python3.11"
    prefix = tmp_path / "protected"
    prefix.mkdir()
    installer = prefix / "installer-venv"
    runtime_python = prefix / "venv" / "bin" / "python"
    wheelhouse = prefix / "stage" / "wheelhouse"
    project_wheel = wheelhouse / "bluefire_nexus-3.0.0rc2-py3-none-any.whl"
    calls = []

    def create_installer(command, **kwargs):
        calls.append(command)
        assert kwargs["cwd"] == prefix
        if len(calls) == 1:
            assert kwargs["timeout"] == 120
            (installer / "bin").mkdir(parents=True)
            (installer / "bin" / "python").write_text("installer", encoding="utf-8")
            return "installer-ready"
        assert kwargs["timeout"] == 300
        return "installed"

    monkeypatch.setattr(provision, "_run", create_installer)
    output = provision._install_offline_wheel(
        interpreter,
        installer,
        runtime_python,
        wheelhouse,
        project_wheel,
        prefix,
        cwd=prefix,
        env={"LANG": "C"},
    )

    assert output == "installed"
    assert calls == [
        provision._venv_command(interpreter, installer, without_pip=False),
        provision._offline_install_command(
            installer / "bin" / "python", runtime_python, wheelhouse, project_wheel
        ),
    ]
    assert not installer.exists()

    calls.clear()

    def fail_during_install(command, **kwargs):
        calls.append(command)
        if len(calls) == 1:
            assert kwargs["timeout"] == 120
            (installer / "bin").mkdir(parents=True)
            (installer / "bin" / "python").write_text("installer", encoding="utf-8")
            return "installer-ready"
        assert kwargs["timeout"] == 300
        raise RuntimeError("fixed install failure")

    monkeypatch.setattr(provision, "_run", fail_during_install)
    with pytest.raises(RuntimeError, match="fixed install failure"):
        provision._install_offline_wheel(
            interpreter,
            installer,
            runtime_python,
            wheelhouse,
            project_wheel,
            prefix,
            cwd=prefix,
            env={"LANG": "C"},
        )

    assert len(calls) == 2
    assert calls[1] == provision._offline_install_command(
        installer / "bin" / "python", runtime_python, wheelhouse, project_wheel
    )
    assert not installer.exists()


def test_import_custody_inventory_counts_package_and_compiled_runtime_files(tmp_path, monkeypatch):
    assert provision._PACKAGE_IMPORT_FILE_LIMIT == local._MAX_IMPORT_FILES
    assert provision._RUNTIME_IMPORT_BYTE_LIMIT == local._MAX_IMPORT_BYTES
    assert provision._RUNTIME_IMPORT_FILE_LIMIT == 4096
    prefix = tmp_path / "protected"
    package_root = prefix / "venv" / "lib" / "python3.11" / "site-packages"
    runtime_root = prefix / "cpython" / "lib" / "python3.11"
    package_root.mkdir(parents=True)
    runtime_root.mkdir(parents=True)
    (package_root / "application.py").write_text("", encoding="utf-8")
    (package_root / "application.pyc").write_bytes(b"bytecode")
    (package_root / "extension.so").write_bytes(b"extension")
    (runtime_root / "stdlib.py").write_text("", encoding="utf-8")
    (runtime_root / "stdlib.pyc").write_bytes(b"bytecode")
    (runtime_root / "extension.so").write_bytes(b"extension")
    archive = prefix / "cpython" / "lib" / "python311.zip"
    archive.write_bytes(b"stdlib archive")
    roots = [str(archive), str(runtime_root)]
    monkeypatch.setattr(
        provision.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(
            returncode=0, stdout=json.dumps(roots).encode("ascii"), stderr=b""
        ),
    )

    inventory = provision._import_custody_inventory(prefix / "venv" / "bin" / "python", prefix)

    assert inventory == {
        "schema_version": provision._IMPORT_INVENTORY_SCHEMA,
        "status": "within_limits",
        "failure_stages": [],
        "failure_reasons": [],
        "package_imports": {
            "file_count": 3,
            "byte_count": 17,
            "by_suffix": {".py": 1, ".pyc": 1, ".so": 1, ".zip": 0},
            "truncated": False,
            "file_limit": 1024,
            "byte_limit": 256 * 1024 * 1024,
        },
        "runtime_imports": {
            "file_count": 4,
            "byte_count": 31,
            "by_suffix": {".py": 1, ".pyc": 1, ".so": 1, ".zip": 1},
            "truncated": False,
            "current_root_file_count": 3,
            "current_root_byte_count": 17,
            "file_limit": 4096,
            "byte_limit": 256 * 1024 * 1024,
            "root_count": 2,
            "not_scanned": False,
        },
    }


def test_import_custody_limit_failure_is_fixed_label_and_path_free(tmp_path, monkeypatch):
    prefix = tmp_path / "protected"
    package_root = prefix / "venv" / "lib" / "python3.11" / "site-packages"
    runtime_root = prefix / "cpython" / "lib" / "python3.11"
    package_root.mkdir(parents=True)
    runtime_root.mkdir(parents=True)
    for index in range(provision._PACKAGE_IMPORT_FILE_LIMIT + 100):
        (package_root / f"module-{index}.py").write_text("", encoding="utf-8")
    (runtime_root / "stdlib.pyc").write_bytes(b"bytecode")
    monkeypatch.setattr(
        provision.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(
            returncode=0, stdout=json.dumps([str(runtime_root)]).encode("ascii"), stderr=b""
        ),
    )

    inventory = provision._import_custody_inventory(prefix / "venv" / "bin" / "python", prefix)
    error = provision.ImportInventoryLimitError(inventory)
    failure_text = json.dumps(provision._failure_document(error), sort_keys=True)

    assert inventory["status"] == "limit_exceeded"
    assert inventory["failure_stages"] == ["package_import_custody"]
    assert inventory["failure_reasons"] == ["package_file_limit_exceeded"]
    assert inventory["package_imports"]["file_count"] == provision._PACKAGE_IMPORT_FILE_LIMIT + 1
    assert inventory["package_imports"]["truncated"] is True
    assert "module-" not in failure_text
    assert str(tmp_path) not in failure_text
    assert "package_import_custody" in failure_text


def test_bounded_inventory_stops_streaming_at_byte_limit(tmp_path, monkeypatch):
    prefix = tmp_path / "protected"
    root = prefix / "imports"
    root.mkdir(parents=True)
    visited = 0

    def many_small_imports(_root, _prefix):
        nonlocal visited
        for index in range(5000):
            visited += 1
            yield prefix / f"module-{index}.py", ".py", 65_537

    monkeypatch.setattr(provision, "_importable_tree_files", many_small_imports)

    summary, failure = provision._bounded_import_counts(
        root,
        prefix,
        file_limit=provision._RUNTIME_IMPORT_FILE_LIMIT,
        byte_limit=provision._RUNTIME_IMPORT_BYTE_LIMIT,
    )

    assert failure == "byte_limit_exceeded"
    assert visited == 4096
    assert summary["file_count"] == visited
    assert summary["byte_count"] == 65_537 * visited
    assert summary["truncated"] is True


def test_runtime_inventory_preserves_overlapping_root_key_and_byte_semantics(tmp_path, monkeypatch):
    prefix = tmp_path / "protected"
    package_root = prefix / "venv" / "lib" / "python3.11" / "site-packages"
    runtime_root = prefix / "cpython" / "lib" / "python3.11"
    alias_parent = runtime_root.parent / "alias"
    package_root.mkdir(parents=True)
    runtime_root.mkdir(parents=True)
    alias_parent.mkdir()
    source = runtime_root / "stdlib.py"
    source.write_bytes(b"runtime")
    overlapping_root = alias_parent / ".." / runtime_root.name
    roots = [str(runtime_root), str(overlapping_root)]
    monkeypatch.setattr(
        provision, "_runtime_import_roots", lambda _python: [Path(x) for x in roots]
    )

    inventory = provision._import_custody_inventory(prefix / "venv" / "bin" / "python", prefix)

    assert inventory["status"] == "within_limits"
    assert inventory["runtime_imports"]["root_count"] == 2
    assert inventory["runtime_imports"]["file_count"] == 2
    assert inventory["runtime_imports"]["byte_count"] == 2 * source.stat().st_size
    assert inventory["runtime_imports"]["by_suffix"][".py"] == 2


def test_installer_environment_cleanup_is_limited_to_exact_owned_child(tmp_path):
    prefix = tmp_path / "protected"
    installer = prefix / "installer-venv"
    runtime = prefix / "venv"
    installer.mkdir(parents=True)
    runtime.mkdir()
    (installer / "python.py").write_text("installer", encoding="utf-8")
    (runtime / "python.py").write_text("runtime", encoding="utf-8")

    provision._remove_owned_installer_venv(installer, prefix)

    assert not installer.exists()
    assert (runtime / "python.py").read_text(encoding="utf-8") == "runtime"


def test_installer_environment_cleanup_rejects_outside_target(tmp_path):
    prefix = tmp_path / "protected"
    outside = tmp_path / "other-installer"
    prefix.mkdir()
    outside.mkdir()
    (outside / "retain.py").write_text("retained", encoding="utf-8")

    with pytest.raises(ValueError, match="installer_environment_identity_invalid"):
        provision._remove_owned_installer_venv(outside, prefix)

    assert (outside / "retain.py").read_text(encoding="utf-8") == "retained"


def test_installer_environment_cleanup_unlinks_only_contained_python_symlinks(tmp_path):
    prefix = tmp_path / "protected"
    installer = prefix / "installer-venv"
    runtime_python = prefix / "cpython" / "bin" / "python3.11"
    installer.mkdir(parents=True)
    runtime_python.parent.mkdir(parents=True)
    runtime_python.write_text("runtime", encoding="utf-8")
    try:
        os.symlink(runtime_python, installer / "python")
    except (NotImplementedError, OSError) as error:
        pytest.skip(f"Symlink creation is unavailable: {type(error).__name__}")

    provision._remove_owned_installer_venv(installer, prefix)

    assert not installer.exists()
    assert runtime_python.read_text(encoding="utf-8") == "runtime"


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


def test_otool_load_command_parsers_capture_rpaths_and_dependencies():
    load_commands = """Load command 2
      cmd LC_RPATH
  cmdsize 48
     path @loader_path/../lib (offset 12)
Load command 3
      cmd LC_RPATH
  cmdsize 40
     path @executable_path/../lib (offset 12)
Load command 4
      cmd LC_LOAD_DYLIB
  cmdsize 72
     name @rpath/libcrypto.3.dylib (offset 24)
Load command 5
      cmd LC_LOAD_WEAK_DYLIB
  cmdsize 72
     name /usr/lib/libSystem.B.dylib (offset 24)
Load command 6
      cmd LC_REEXPORT_DYLIB
  cmdsize 72
     name @rpath/libreexport.dylib (offset 24)
Load command 7
      cmd LC_LOAD_UPWARD_DYLIB
  cmdsize 72
     name @rpath/libupward.dylib (offset 24)
Load command 8
      cmd LC_LAZY_LOAD_DYLIB
  cmdsize 72
     name @rpath/liblazy.dylib (offset 24)
"""

    assert provision._parse_lc_rpaths(load_commands) == [
        "@loader_path/../lib",
        "@executable_path/../lib",
    ]
    assert provision._parse_lc_dylib_dependencies(load_commands) == [
        "@rpath/libcrypto.3.dylib",
        "/usr/lib/libSystem.B.dylib",
        "@rpath/libreexport.dylib",
        "@rpath/libupward.dylib",
        "@rpath/liblazy.dylib",
    ]


def test_lc_dylib_parser_excludes_id_but_preserves_identical_dependency():
    install_name = "@rpath/cryptography.hazmat.bindings._rust.abi3.so"
    load_commands = f"""Load command 1
      cmd LC_ID_DYLIB
  cmdsize 80
     name {install_name} (offset 24)
Load command 2
      cmd LC_LOAD_DYLIB
  cmdsize 80
     name {install_name} (offset 24)
Load command 3
      cmd LC_LOAD_DYLIB
  cmdsize 72
     name @rpath/libcrypto.3.dylib (offset 24)
"""

    # Only LC_LOAD_* roles are checked as dependencies. Even the same string
    # remains a dependency when it appears under LC_LOAD_DYLIB.
    assert provision._parse_lc_dylib_dependencies(load_commands) == [
        install_name,
        "@rpath/libcrypto.3.dylib",
    ]


def test_lc_dylib_parser_fails_closed_before_a_following_command_name():
    load_commands = """Load command 0
      cmd LC_ID_DYLIB
  cmdsize 48
     name @rpath/image.dylib (offset 24)
Load command 1
      cmd LC_LOAD_DYLIB
  cmdsize 24
Load command 2
      cmd LC_ID_DYLIB
  cmdsize 64
     name @rpath/unrelated.dylib (offset 24)
"""

    with pytest.raises(ValueError, match="has no install name"):
        provision._parse_lc_dylib_dependencies(load_commands)


def test_lc_dylib_parser_preserves_install_name_spaces():
    load_commands = """Load command 0
      cmd LC_LOAD_DYLIB
  cmdsize 72
     name @rpath/Library With Spaces.dylib (offset 24)
"""

    assert provision._parse_lc_dylib_dependencies(load_commands) == [
        "@rpath/Library With Spaces.dylib"
    ]


def test_lc_dylib_parser_keeps_each_fat_slice_dependency():
    load_commands = """/runtime/_rust.abi3.so (architecture arm64):
Load command 0
      cmd LC_ID_DYLIB
  cmdsize 64
     name @rpath/_rust.abi3.so (offset 24)
Load command 1
      cmd LC_LOAD_DYLIB
  cmdsize 72
     name @rpath/arm64/libcrypto.dylib (offset 24)
/runtime/_rust.abi3.so (architecture x86_64):
Load command 0
      cmd LC_ID_DYLIB
  cmdsize 64
     name @rpath/_rust.abi3.so (offset 24)
Load command 1
      cmd LC_LOAD_DYLIB
  cmdsize 72
     name @rpath/x86_64/libcrypto.dylib (offset 24)
"""

    assert provision._parse_lc_dylib_dependencies(load_commands) == [
        "@rpath/arm64/libcrypto.dylib",
        "@rpath/x86_64/libcrypto.dylib",
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
        process, queue.Queue(), queue.Queue(), queue.Queue(), (_Reader(), _Reader())
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
        process,
        queue.Queue(),
        queue.Queue(),
        queue.Queue(),
        (_Reader(alive=True), _Reader(alive=True)),
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


def test_child_cli_error_retains_only_known_safe_classification():
    parsed = lifecycle._parse_child_cli_error(
        '{"error":{"code":"command_failed","message":"The local identity inventory is unavailable."}}'
    )

    assert parsed == {
        "error_code": "command_failed",
        "error_class": "local_identity_inventory_unavailable",
    }


def test_child_cli_error_keeps_only_allowlisted_setup_stage():
    parsed = lifecycle._parse_child_cli_error(
        json.dumps(
            {
                "error": {
                    "code": "command_failed",
                    "message": "The protected macOS setup is unavailable.",
                    "setup_stage": "package_import_custody",
                    "setup_site": "package_acl_policy",
                    "setup_offset": 33,
                    "details": {"path": "/private/var/db/private-workspace"},
                }
            }
        )
    )
    unknown_stage = lifecycle._parse_child_cli_error(
        json.dumps(
            {
                "error": {
                    "code": "command_failed",
                    "message": "The protected macOS setup is unavailable.",
                    "setup_stage": "/private/var/db/private-workspace",
                    "setup_site": "/private/var/db/private-workspace",
                    "setup_offset": 999,
                }
            }
        )
    )
    invalid_offset = lifecycle._parse_child_cli_error(
        json.dumps(
            {
                "error": {
                    "code": "command_failed",
                    "message": "The protected macOS setup is unavailable.",
                    "setup_stage": "package_import_custody",
                    "setup_site": "package_acl_policy",
                    "setup_offset": 999,
                }
            }
        )
    )
    bool_offset = lifecycle._parse_child_cli_error(
        json.dumps(
            {
                "error": {
                    "code": "command_failed",
                    "message": "The protected macOS setup is unavailable.",
                    "setup_stage": "package_import_custody",
                    "setup_site": "package_acl_policy",
                    "setup_offset": True,
                }
            }
        )
    )
    namespace_site = lifecycle._parse_child_cli_error(
        json.dumps(
            {
                "error": {
                    "code": "command_failed",
                    "message": "The original sealed Darwin namespace is unavailable.",
                    "setup_stage": "namespace_creation",
                    "setup_site": "namespace_worker_start",
                    "setup_offset": 121,
                }
            }
        )
    )
    cross_stage_site = lifecycle._parse_child_cli_error(
        json.dumps(
            {
                "error": {
                    "code": "command_failed",
                    "message": "The protected macOS setup is unavailable.",
                    "setup_stage": "namespace_creation",
                    "setup_site": "package_acl_policy",
                    "setup_offset": 33,
                }
            }
        )
    )

    assert parsed == {
        "error_code": "command_failed",
        "error_class": "protected_setup_unavailable",
        "setup_stage": "package_import_custody",
        "setup_site": "package_acl_policy",
        "setup_offset": 33,
    }
    assert unknown_stage == {
        "error_code": "command_failed",
        "error_class": "protected_setup_unavailable",
    }
    assert invalid_offset == {
        "error_code": "command_failed",
        "error_class": "protected_setup_unavailable",
        "setup_stage": "package_import_custody",
    }
    assert bool_offset == {
        "error_code": "command_failed",
        "error_class": "protected_setup_unavailable",
        "setup_stage": "package_import_custody",
    }
    assert namespace_site == {
        "error_code": "command_failed",
        "error_class": "unclassified_command_failure",
        "setup_stage": "namespace_creation",
        "setup_site": "namespace_worker_start",
        "setup_offset": 121,
    }
    assert cross_stage_site == {
        "error_code": "command_failed",
        "error_class": "protected_setup_unavailable",
        "setup_stage": "namespace_creation",
    }
    assert local.MACOS_SETUP_DIAGNOSTIC_STAGES == lifecycle._SAFE_SETUP_STAGES
    assert local.MACOS_SETUP_DIAGNOSTIC_SITE_OFFSETS == lifecycle._SAFE_SETUP_SITE_OFFSETS


def test_child_cli_error_redacts_unclassified_message_and_rejects_other_codes():
    secret_message = (
        "failed at /private/var/db/private-workspace using "
        "http://127.0.0.1:4312/#bluefire-session=secret-capability"
    )
    parsed = lifecycle._parse_child_cli_error(
        json.dumps({"error": {"code": "command_failed", "message": secret_message}})
    )
    serialized = json.dumps(parsed)

    assert parsed == {
        "error_code": "command_failed",
        "error_class": "unclassified_command_failure",
    }
    assert all(
        unsafe not in serialized
        for unsafe in ("private-workspace", "127.0.0.1", "secret-capability")
    )
    assert (
        lifecycle._parse_child_cli_error('{"error":{"code":"arbitrary_code","message":"unsafe"}}')
        is None
    )


def _pretty_cli_json(value):
    output = io.StringIO()
    with redirect_stdout(output):
        cli._json(value)
    return output.getvalue()


def test_stdout_reader_parses_pretty_printed_cli_error_after_eof():
    raw = _pretty_cli_json(
        {
            "error": {
                "code": "command_failed",
                "message": "The local identity inventory is unavailable.",
                "setup_stage": "local_account_inventory",
            }
        }
    )
    stdout = queue.Queue(maxsize=1)
    child_errors = queue.Queue(maxsize=1)

    lifecycle._read_supervisor_stdout(io.StringIO(raw), stdout, child_errors)

    assert stdout.empty()
    assert child_errors.get_nowait() == {
        "error_code": "command_failed",
        "error_class": "local_identity_inventory_unavailable",
        "setup_stage": "local_account_inventory",
    }


def test_stdout_reader_preserves_pretty_printed_supervisor_result():
    document = {
        "schema_version": "bluefire.macos-file-access-local-supervisor-result.v1",
        "status": "stopped_cleanly",
        "host": {"host_closed": True},
        "components": {"workers_closed": True},
        "generated_resource": {"resource_retained": True},
        "workspace_retained": True,
        "identity_accounts_created": False,
    }
    raw = _pretty_cli_json(document)
    stdout = queue.Queue(maxsize=1)
    child_errors = queue.Queue(maxsize=1)

    lifecycle._read_supervisor_stdout(io.StringIO(raw), stdout, child_errors)

    assert json.loads(stdout.get_nowait()) == document
    assert child_errors.empty()


@pytest.mark.parametrize(
    "raw",
    [
        '{"schema_version": "bluefire.macos-file-access-local-supervisor-result.v1"',
        _pretty_cli_json({"schema_version": "unknown.result.v1", "status": "passed"}),
    ],
)
def test_stdout_reader_discards_malformed_and_unknown_documents(raw):
    stdout = queue.Queue(maxsize=1)
    child_errors = queue.Queue(maxsize=1)

    lifecycle._read_supervisor_stdout(io.StringIO(raw), stdout, child_errors)

    assert stdout.empty()
    assert child_errors.empty()


def test_stdout_reader_drains_but_does_not_retain_over_limit_document():
    prefix = _pretty_cli_json(
        {"schema_version": "bluefire.macos-file-access-local-supervisor-result.v1"}
    )
    raw = prefix + (" " * lifecycle.MAX_BODY)
    stream = io.StringIO(raw)
    stdout = queue.Queue(maxsize=1)
    child_errors = queue.Queue(maxsize=1)

    lifecycle._read_supervisor_stdout(stream, stdout, child_errors)

    assert stream.tell() == len(raw)
    assert stdout.empty()
    assert child_errors.empty()


def test_readiness_failure_diagnostics_keep_specific_stage_and_fixed_fields_only():
    diagnostics = lifecycle._safe_readiness_diagnostics(
        "child_exited_before_readiness",
        {
            "shutdown_method": "supervisor_sigterm",
            "supervisor_returncode": 2,
            "process_group_gone": True,
            "streams_drained": True,
            "stdout": "http://127.0.0.1:4312/#bluefire-session=secret-capability",
        },
        {
            "error_code": "command_failed",
            "error_class": "unclassified_command_failure",
            "setup_stage": "native_runner_initialization",
            "setup_site": "package_acl_policy",
            "setup_offset": 33,
            "message": "/private/var/db/private-workspace",
        },
    )

    assert diagnostics == {
        "failure_stage": "child_exited_before_readiness",
        "shutdown_method": "supervisor_sigterm",
        "process_group_gone": True,
        "streams_drained": True,
        "supervisor_returncode": 2,
        "error_code": "command_failed",
        "error_class": "unclassified_command_failure",
        "setup_stage": "native_runner_initialization",
    }


def test_readiness_diagnostics_fall_back_on_malformed_field_types():
    diagnostics = lifecycle._safe_readiness_diagnostics(
        ["child_exited_before_readiness"],
        {
            "shutdown_method": ["supervisor_sigterm"],
            "process_group_gone": "true",
            "streams_drained": 1,
            "supervisor_returncode": True,
        },
        {
            "error_code": "command_failed",
            "error_class": ["unsafe"],
            "setup_stage": "/private/var/db/private-workspace",
        },
    )

    assert diagnostics == {"failure_stage": "readiness_wait"}


def test_readiness_diagnostics_keep_only_a_known_package_site_and_bounded_offset():
    diagnostics = lifecycle._safe_readiness_diagnostics(
        "child_exited_before_readiness",
        {},
        {
            "error_code": "command_failed",
            "error_class": "protected_setup_unavailable",
            "setup_stage": "package_import_custody",
            "setup_site": "package_acl_policy",
            "setup_offset": 33,
            "raw_message": "private path and capability data",
        },
    )

    assert diagnostics == {
        "failure_stage": "child_exited_before_readiness",
        "error_code": "command_failed",
        "error_class": "protected_setup_unavailable",
        "setup_stage": "package_import_custody",
        "setup_site": "package_acl_policy",
        "setup_offset": 33,
    }


def test_readiness_diagnostics_keep_namespace_site_only_for_namespace_stage():
    diagnostics = lifecycle._safe_readiness_diagnostics(
        "child_exited_before_readiness",
        {},
        {
            "error_code": "command_failed",
            "error_class": "unclassified_command_failure",
            "setup_stage": "namespace_creation",
            "setup_site": "namespace_worker_start",
            "setup_offset": 121,
            "raw_message": "private path and capability data",
        },
    )

    assert diagnostics == {
        "failure_stage": "child_exited_before_readiness",
        "error_code": "command_failed",
        "error_class": "unclassified_command_failure",
        "setup_stage": "namespace_creation",
        "setup_site": "namespace_worker_start",
        "setup_offset": 121,
    }
