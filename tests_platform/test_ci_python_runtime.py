"""CI runtime guards and authored child fixtures; no download or relocation."""

from __future__ import annotations

import importlib.util
import json
import math
import os
import stat
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
LINUX = pytest.mark.skipif(sys.platform != "linux", reason="Linux filesystem policy")


@pytest.fixture
def runtime():
    spec = importlib.util.spec_from_file_location(
        "ci_python_runtime_under_test", ROOT / "tools/prepare_ci_python.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _elf(kind=3, endian=1):
    header = bytearray(18)
    header[:6] = b"\x7fELF\x02" + bytes([endian])
    header[16:18] = kind.to_bytes(2, "little" if endian == 1 else "big")
    return bytes(header)


@pytest.fixture
def tree(tmp_path):
    root = tmp_path / "cache"
    prefix = root / "Python" / "3.10.11" / "x64"
    (prefix / "bin").mkdir(parents=True)
    (prefix / "lib").mkdir()
    for path in (root, root / "Python", prefix.parent, prefix, prefix / "bin", prefix / "lib"):
        path.chmod(0o700)
    interpreter = prefix / "bin" / "python"
    interpreter.write_bytes(_elf(2))
    interpreter.chmod(0o700)
    library = prefix / "lib" / "libpython3.10.so"
    library.write_bytes(_elf(3))
    library.chmod(0o600)
    return SimpleNamespace(root=root, prefix=prefix, interpreter=interpreter, library=library)


@pytest.mark.parametrize("suffix", ["/../escape", "/has space", "/bad\nline", "/bad\x00value"])
def test_path_rejects_traversal_and_control_content(runtime, suffix):
    value = str(Path(Path.cwd().anchor) / "ci-cache") + suffix
    with pytest.raises(runtime.Refusal, match="^invalid_path$"):
        runtime._path(value)


@pytest.mark.parametrize("value", ["", "relative/cache"])
def test_path_requires_absolute_location(runtime, value):
    with pytest.raises(runtime.Refusal, match="^absolute_path_required$"):
        runtime._path(value)


@pytest.mark.parametrize(
    ("ancestor_mode", "ancestor_uid", "root_mode", "root_uid", "token", "error"),
    [
        (stat.S_IFDIR | 0o1777, 0, 0o700, 100, "1:2:100", None),
        (stat.S_IFDIR | 0o777, 0, 0o700, 100, "1:2:100", "ancestor_writable"),
        (stat.S_IFDIR | 0o755, 200, 0o700, 100, "1:2:100", "ancestor_owner"),
        (stat.S_IFLNK | 0o777, 100, 0o700, 100, "1:2:100", "ancestor_not_directory"),
        (stat.S_IFDIR | 0o755, 0, 0o755, 100, "1:2:100", "cache_mode"),
        (stat.S_IFDIR | 0o755, 0, 0o700, 0, "1:2:0", "cache_mode"),
        (stat.S_IFDIR | 0o755, 0, 0o700, 100, "1:99:100", "cache_identity"),
        (stat.S_IFDIR | 0o1777, 0, 0o1777, 100, "1:2:100", "ancestor_writable"),
    ],
)
def test_root_requires_protected_ancestors_private_mode_and_exact_identity(
    runtime, monkeypatch, ancestor_mode, ancestor_uid, root_mode, root_uid, token, error
):
    ancestor = SimpleNamespace(
        lstat=lambda: SimpleNamespace(st_mode=ancestor_mode, st_uid=ancestor_uid)
    )
    root = SimpleNamespace(
        parents=(ancestor,),
        lstat=lambda: SimpleNamespace(
            st_mode=stat.S_IFDIR | root_mode, st_uid=root_uid, st_dev=1, st_ino=2
        ),
    )
    monkeypatch.setattr(runtime, "os", SimpleNamespace(getuid=lambda: 100))
    if error:
        with pytest.raises(runtime.Refusal, match=f"^{error}$"):
            runtime._root(root, token)
    else:
        runtime._root(root, token)


@LINUX
def test_root_refuses_recreated_directory_with_old_identity(runtime, tree):
    info = tree.root.lstat()
    token = f"{info.st_dev}:{info.st_ino}:{info.st_uid}"
    runtime._root(tree.root, token)
    tree.root.rename(tree.root.with_name("old-cache"))
    tree.root.mkdir(mode=0o700)
    with pytest.raises(runtime.Refusal, match="^cache_identity$"):
        runtime._root(tree.root, token)


@LINUX
def test_prefix_and_inventory_refuse_interpreter_link_escape(runtime, tree, tmp_path):
    assert runtime._prefix(tree.root, tree.interpreter) == tree.prefix
    tree.interpreter.unlink()
    outside = tmp_path / "outside-python"
    outside.write_bytes(_elf(2))
    tree.interpreter.symlink_to(outside)
    with pytest.raises(runtime.Refusal, match="^interpreter_link_escape$"):
        runtime._prefix(tree.root, tree.interpreter)


@pytest.mark.parametrize(
    ("relative", "error"),
    [
        ("Other/3.10.11/x64/bin/python", "interpreter_layout"),
        ("Python/3.13.1/x64/bin/python", "interpreter_version"),
        ("Python/3.10.11/x64/python", "interpreter_layout"),
    ],
)
def test_prefix_refuses_unrecognized_layout_before_inspection(runtime, relative, error):
    root = Path(Path.cwd().anchor) / "private-ci-cache"
    with pytest.raises(runtime.Refusal, match=f"^{error}$"):
        runtime._prefix(root, root / relative)
    with pytest.raises(runtime.Refusal, match="^interpreter_outside_cache$"):
        runtime._prefix(root, root.parent / "other-cache" / "python")


@pytest.mark.parametrize(("kind", "expected"), [(1, False), (2, True), (3, True)])
@pytest.mark.parametrize("endian", [1, 2])
def test_only_executable_and_shared_elfs_are_runtime_inputs(runtime, kind, expected, endian):
    assert runtime._runtime_elf(_elf(kind, endian)) is expected
    assert runtime._runtime_elf(b"plain data") is False


@pytest.mark.parametrize("header", [b"\x7fELF", _elf(0), _elf(4), b"\x7fELF\x00\x01" + bytes(12)])
def test_malformed_or_unknown_elf_is_refused(runtime, header):
    with pytest.raises(runtime.Refusal, match="^invalid_elf$"):
        runtime._runtime_elf(header)


@LINUX
def test_inventory_retains_build_input_identity_without_relocating_et_rel(runtime, tree):
    object_file = tree.prefix / "lib" / "python.o"
    object_file.write_bytes(_elf(1))
    object_file.chmod(0o600)
    elfs, identities = runtime._inventory(tree.prefix, runtime.time.monotonic() + 10)
    assert set(elfs) == {tree.interpreter, tree.library}
    assert object_file in identities


@LINUX
def test_inventory_refuses_hardlinked_runtime_before_any_mutation(runtime, tree):
    os.link(tree.library, tree.prefix / "lib" / "duplicate.so")
    original = tree.library.read_bytes()
    with pytest.raises(runtime.Refusal, match="^runtime_hardlink$"):
        runtime._inventory(tree.prefix, runtime.time.monotonic() + 10)
    assert tree.library.read_bytes() == original


@LINUX
def test_inventory_refuses_outside_bridge_even_when_final_target_is_inside(runtime, tree, tmp_path):
    bridge = tmp_path / "outside-bridge"
    bridge.symlink_to(tree.library)
    (tree.prefix / "lib" / "escape-and-return.so").symlink_to(bridge)
    with pytest.raises(runtime.Refusal, match="^runtime_link_escape$"):
        runtime._inventory(tree.prefix, runtime.time.monotonic() + 10)


@LINUX
@pytest.mark.parametrize(
    ("limit", "value", "error"),
    [
        ("MAX_ENTRIES", 0, "runtime_entry_limit"),
        ("MAX_ELFS", 0, "runtime_elf_limit"),
        ("MAX_FILE_BYTES", 17, "runtime_size_limit"),
        ("MAX_TOTAL_BYTES", 17, "runtime_size_limit"),
    ],
)
def test_inventory_honors_each_finite_budget(runtime, tree, monkeypatch, limit, value, error):
    monkeypatch.setattr(runtime, limit, value)
    with pytest.raises(runtime.Refusal, match=f"^{error}$"):
        runtime._inventory(tree.prefix, runtime.time.monotonic() + 10)


def test_remaining_budget_is_positive_finite_and_capped(runtime, monkeypatch):
    monkeypatch.setattr(runtime, "time", SimpleNamespace(monotonic=lambda: 100.0))
    assert runtime._remaining(100.125) == 0.125
    assert runtime._remaining(1000.0) == 10.0
    assert math.isfinite(runtime._remaining(math.inf))
    for deadline in (100.0, 99.0, math.nan):
        with pytest.raises(runtime.Refusal, match="^runtime_deadline$"):
            runtime._remaining(deadline)


@LINUX
def test_rpath_rewrites_only_expected_cache_and_preserves_private_origin(runtime, tree):
    old = "/opt/hostedtoolcache/Python/3.10.11/x64/lib"
    assert runtime._rpath(old, tree.interpreter, tree.prefix) == str(tree.prefix / "lib")
    for origin in ("$ORIGIN/../lib", "${ORIGIN}/../lib"):
        assert runtime._rpath(origin, tree.interpreter, tree.prefix) == origin
    assert runtime._rpath("", tree.interpreter, tree.prefix) == ""
    for invalid in ("relative", "$LIB", old + ":", "/usr/lib"):
        with pytest.raises(runtime.Refusal, match="^unrecognized_rpath$"):
            runtime._rpath(invalid, tree.interpreter, tree.prefix)


@LINUX
def test_rpath_refuses_outside_bridge_even_when_final_target_is_private(runtime, tree, tmp_path):
    bridge = tmp_path / "outside-library-bridge"
    bridge.symlink_to(tree.prefix / "lib", target_is_directory=True)
    with pytest.raises(runtime.Refusal, match="^unrecognized_rpath$"):
        runtime._rpath(str(bridge), tree.interpreter, tree.prefix)


@pytest.mark.parametrize("failure", [None, "output_limit", "deadline", "exit_status"])
def test_child_uses_clean_environment_and_bounded_output_waits(runtime, monkeypatch, failure):
    calls = []
    child = SimpleNamespace(
        pid=73,
        stdout=SimpleNamespace(fileno=lambda: 42, close=lambda: calls.append(("close",))),
        finished=False,
    )

    def wait(timeout):
        calls.append(("wait", timeout))
        child.finished = True
        return 1 if failure == "exit_status" else 0

    child.wait = wait
    child.poll = lambda: pytest.fail("Leader must not be reaped before group cleanup")

    def popen(args, **kwargs):
        calls.append(("spawn", args, kwargs))
        return child

    def waitid(kind, pid, flags):
        assert (kind, pid, flags) == (1, 73, 2 | 4 | 8)
        calls.append(("observe_without_reap",))
        return SimpleNamespace(si_pid=73, si_code=1, si_status=1 if failure == "exit_status" else 0)

    class Selector:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def register(self, *_args):
            pass

        def select(self, timeout):
            assert 0 < timeout <= 4.0
            return [] if failure == "deadline" else [(None, None)]

    chunks = iter(
        [b"x" * (runtime.MAX_OUTPUT_BYTES + 1) if failure == "output_limit" else b"ok", b""]
    )
    monkeypatch.setenv("LD_PRELOAD", "untrusted-parent-value")
    monkeypatch.setenv("LD_LIBRARY_PATH", "untrusted-parent-value")
    monkeypatch.setattr(runtime, "time", SimpleNamespace(monotonic=lambda: 100.0))
    monkeypatch.setattr(
        runtime,
        "os",
        SimpleNamespace(
            set_blocking=lambda *_: None,
            read=lambda *_: next(chunks),
            P_PID=1,
            WEXITED=2,
            WNOHANG=4,
            WNOWAIT=8,
            CLD_EXITED=1,
            waitid=waitid,
            killpg=lambda pid, signal: calls.append(("killpg", pid, signal)),
        ),
    )
    monkeypatch.setattr(runtime, "signal", SimpleNamespace(SIGKILL=9))
    monkeypatch.setattr(runtime, "subprocess", SimpleNamespace(Popen=popen, DEVNULL=-3, PIPE=-1))
    monkeypatch.setattr(
        runtime, "selectors", SimpleNamespace(DefaultSelector=Selector, EVENT_READ=1)
    )
    errors = {
        "output_limit": "child_output_limit",
        "deadline": "child_deadline",
        "exit_status": "child_failed",
    }
    if failure:
        with pytest.raises(runtime.Refusal, match=f"^{errors[failure]}$"):
            runtime._run(["owned-child"], Path.cwd(), 104.0)
    else:
        assert runtime._run(["owned-child"], Path.cwd(), 104.0) == b"ok"
    environment = calls[0][2]["env"]
    assert environment == {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}
    assert calls[0][2]["start_new_session"] is True
    assert all(0 < call[1] <= 5 for call in calls if call[0] == "wait")
    assert ("killpg", 73, 9) in calls and child.finished
    assert next(i for i, call in enumerate(calls) if call[0] == "killpg") < next(
        i for i, call in enumerate(calls) if call[0] == "wait"
    )


def test_cleanup_timeout_is_unknown_and_does_not_renew_budget(runtime, monkeypatch):
    calls = []

    def wait(timeout):
        assert timeout == pytest.approx(0.125)
        calls.append("wait")
        raise runtime.subprocess.TimeoutExpired("authored-child", timeout)

    monkeypatch.setattr(runtime, "time", SimpleNamespace(monotonic=lambda: 103.875))
    monkeypatch.setattr(runtime, "os", SimpleNamespace(killpg=lambda *_: calls.append("killpg")))
    monkeypatch.setattr(runtime, "signal", SimpleNamespace(SIGKILL=9))
    with pytest.raises(runtime.Refusal, match="^child_cleanup_unknown$"):
        runtime._terminate_group(SimpleNamespace(pid=73, wait=wait), 104.0)
    assert calls == ["killpg", "wait"]


@LINUX
@pytest.mark.parametrize("keep_pipe", [False, True])
def test_run_kills_descendant_after_leader_exits(runtime, tmp_path, keep_pipe):
    """A real authored fork cannot survive successful EOF or retained-pipe refusal."""
    receipt = tmp_path / "child.json"
    script = r"""
import json, os, pathlib, sys, time
r, w = os.pipe()
if os.fork() == 0:
    os.close(r)
    fields = pathlib.Path('/proc/self/stat').read_text().rsplit(')', 1)[1].split()
    pathlib.Path(sys.argv[1]).write_text(json.dumps({'pid': os.getpid(), 'start': fields[19]}))
    os.write(w, b'1')
    os.close(w)
    if sys.argv[2] == 'close':
        os.close(1)
    time.sleep(20)
    os._exit(0)
os.close(w)
assert os.read(r, 1) == b'1'
os.close(r)
os.write(1, b'ok\n')
os._exit(0)
"""
    arguments = [
        sys.executable,
        "-I",
        "-B",
        "-c",
        script,
        str(receipt),
        "keep" if keep_pipe else "close",
    ]
    began = time.monotonic()

    def live_owned_child():
        if not receipt.exists():
            return None
        identity = json.loads(receipt.read_text())
        try:
            fields = (
                (Path("/proc") / str(identity["pid"]) / "stat")
                .read_text()
                .rsplit(")", 1)[1]
                .split()
            )
        except FileNotFoundError:
            return None
        return identity["pid"] if fields[19] == identity["start"] and fields[0] != "Z" else None

    try:
        if keep_pipe:
            with pytest.raises(runtime.Refusal, match="^child_deadline$"):
                runtime._run(arguments, tmp_path, began + 3)
        else:
            assert runtime._run(arguments, tmp_path, began + 3) == b"ok\n"
        assert time.monotonic() - began < 4
        assert receipt.exists()
        stop = time.monotonic() + 1
        while live_owned_child() is not None:
            assert time.monotonic() < stop, "Owned child survived process-group cleanup"
            time.sleep(0.01)
    finally:
        # Preserve test cleanup even if a regression leaves the authored child alive.
        pid = live_owned_child()
        if pid is not None:
            os.kill(pid, 9)


@LINUX
@pytest.mark.parametrize("pinned", [False, True])
def test_probe_isolated_arguments_and_owned_descriptor_are_closed(
    runtime, tree, monkeypatch, pinned
):
    observed = {}

    def run(args, root, deadline, **kwargs):
        observed.update(args=args, root=root, deadline=deadline, **kwargs)
        assert args[1:4] == ["-I", "-B", "-c"]
        assert args[-2:] == [str(tree.prefix), str(tree.interpreter)]
        if pinned:
            descriptor = kwargs["pass_fds"][0]
            assert kwargs["executable"] == f"/proc/self/fd/{descriptor}"
            assert os.fstat(descriptor).st_ino == tree.interpreter.stat().st_ino
        else:
            assert kwargs["executable"] is None and kwargs["pass_fds"] == ()
        return b'{"probe":"ok"}\n'

    monkeypatch.setattr(runtime, "_run", run)
    runtime._probe(tree.interpreter, tree.prefix, tree.root, 123.0, pinned=pinned)
    if pinned:
        with pytest.raises(OSError):
            os.fstat(observed["pass_fds"][0])


@pytest.mark.parametrize("failed_probe", [None, False, True])
def test_relocation_exports_only_after_both_probes_succeed(
    runtime, tree, monkeypatch, failed_probe
):
    events = []
    info = tree.library.lstat()
    tool_info = SimpleNamespace(
        st_mode=stat.S_IFREG | 0o755, st_uid=0, st_dev=1, st_ino=2, st_size=0, st_mtime_ns=0
    )
    monkeypatch.setenv("AGENT_TOOLSDIRECTORY", str(tree.root))
    monkeypatch.setenv("BLUEFIRE_CI_PYTHON_CACHE_ID", "fixture-token")
    monkeypatch.setenv("BLUEFIRE_CI_PYTHON_PATH", str(tree.interpreter))
    monkeypatch.setattr(runtime, "_path", Path)
    monkeypatch.setattr(runtime, "_root", lambda *_: None)
    monkeypatch.setattr(runtime, "_prefix", lambda *_: tree.prefix)
    monkeypatch.setattr(runtime, "_ancestors", lambda *_: None)
    monkeypatch.setattr(
        runtime, "PATCHELF", SimpleNamespace(parent=tree.root, lstat=lambda: tool_info)
    )
    monkeypatch.setattr(
        runtime, "_inventory", lambda *_: ([tree.library], {tree.library: runtime._identity(info)})
    )
    monkeypatch.setattr(runtime, "_check_entry", lambda *_: info)
    monkeypatch.setattr(runtime, "_run", lambda *_: b"")

    def probe(interpreter, prefix, root, deadline, pinned):
        assert (interpreter, prefix, root) == (tree.interpreter, tree.prefix, tree.root)
        assert math.isfinite(deadline)
        events.append("pinned" if pinned else "normal")
        if failed_probe is pinned:
            raise runtime.Refusal("probe_output")

    def exports(values, paths=()):
        events.append("exports")
        assert values["pythonLocation"] == values["Python_ROOT_DIR"] == str(tree.prefix)
        assert values["LD_LIBRARY_PATH"] == ""
        assert paths == (tree.prefix, tree.prefix / "bin")

    monkeypatch.setattr(runtime, "_probe", probe)
    monkeypatch.setattr(runtime, "_exports", exports)
    if failed_probe is None:
        runtime.relocate()
        assert events == ["normal", "pinned", "exports"]
    else:
        with pytest.raises(runtime.Refusal, match="^probe_output$"):
            runtime.relocate()
        assert events == (["normal"] if failed_probe is False else ["normal", "pinned"])


@LINUX
def test_failed_probe_output_still_closes_owned_descriptor(runtime, tree, monkeypatch):
    descriptors = []

    def run(*_args, **kwargs):
        descriptors.extend(kwargs["pass_fds"])
        return b'{"probe":"ok"}\nextra output\n'

    monkeypatch.setattr(runtime, "_run", run)
    with pytest.raises(runtime.Refusal, match="^probe_output$"):
        runtime._probe(tree.interpreter, tree.prefix, tree.root, 123.0, pinned=True)
    assert len(descriptors) == 1
    with pytest.raises(OSError):
        os.fstat(descriptors[0])


@pytest.mark.parametrize(
    ("values", "paths", "error"),
    [
        ({"BAD-NAME": "value"}, (), "export_key"),
        ({"GOOD": "value\nINJECTED=1"}, (), "export_value"),
        ({"GOOD": "value"}, (Path("relative"),), "absolute_path_required"),
    ],
)
def test_invalid_exports_leave_both_destination_files_unchanged(
    runtime, tmp_path, monkeypatch, values, paths, error
):
    environment, search_path = tmp_path / "env", tmp_path / "path"
    for path in (environment, search_path):
        path.write_text("retained\n", encoding="utf-8")
    monkeypatch.setenv("GITHUB_ENV", str(environment))
    monkeypatch.setenv("GITHUB_PATH", str(search_path))
    with pytest.raises(runtime.Refusal, match=f"^{error}$"):
        runtime._exports(values, paths)
    assert (
        environment.read_text(encoding="utf-8")
        == search_path.read_text(encoding="utf-8")
        == "retained\n"
    )


def test_prepare_refuses_unsafe_parent_before_creating_or_exporting(runtime, monkeypatch):
    monkeypatch.setenv("RUNNER_TEMP", str(Path(Path.cwd().anchor) / "unsafe-ci-parent"))
    monkeypatch.setattr(runtime, "_diagnose_shared_cache", lambda *_: None)

    def refuse(_parent):
        raise runtime.Refusal("ancestor_writable")

    def forbidden(*_args, **_kwargs):
        pytest.fail("Unsafe parent reached creation or export")

    monkeypatch.setattr(runtime, "_ancestors", refuse)
    monkeypatch.setattr(runtime, "tempfile", SimpleNamespace(mkdtemp=forbidden))
    monkeypatch.setattr(runtime, "_exports", forbidden)
    with pytest.raises(runtime.Refusal, match="^ancestor_writable$"):
        runtime.prepare()


def test_main_reports_static_failure_without_exception_path(runtime, monkeypatch, capsys):
    monkeypatch.setattr(
        runtime, "sys", SimpleNamespace(platform="linux", argv=["helper", "prepare"])
    )

    def fail():
        raise ValueError("PRIVATE_PATH_SENTINEL")

    monkeypatch.setattr(runtime, "prepare", fail)
    assert runtime.main() == 1
    assert json.loads(capsys.readouterr().out) == {
        "stage": "prepare",
        "status": "refused",
        "code": "operation_failed",
    }


@pytest.mark.parametrize("job_name", ["python", "package"])
def test_workflow_exports_linux_runtime_only_after_verification(job_name):
    workflow = yaml.safe_load((ROOT / ".github/workflows/tests.yml").read_text(encoding="utf-8"))
    steps = workflow["jobs"][job_name]["steps"]
    names = [step["name"] for step in steps]
    by_name = {step["name"]: step for step in steps}
    prepare = by_name["Prepare protected Linux Python cache"]
    setup = by_name["Set up Python"]
    verify = by_name["Verify protected Linux Python runtime"]
    assert (
        names.index("Checkout")
        < names.index(prepare["name"])
        < names.index(setup["name"])
        < names.index(verify["name"])
    )
    assert prepare["if"] == verify["if"] == "runner.os == 'Linux'"
    assert prepare["run"] == "/usr/bin/python3 -I -B tools/prepare_ci_python.py prepare"
    assert verify["run"] == "/usr/bin/python3 -I -B tools/prepare_ci_python.py relocate"
    assert setup["id"] == "setup-python"
    assert setup["with"]["update-environment"] == "${{ runner.os != 'Linux' }}"
    assert (
        verify["env"]["BLUEFIRE_CI_PYTHON_PATH"] == "${{ steps.setup-python.outputs.python-path }}"
    )
    first_use = (
        "Install maintained package and tools"
        if job_name == "python"
        else "Archive exact committed wheel source"
    )
    assert names.index(verify["name"]) < names.index(first_use)
    if job_name == "package":
        assert (
            prepare["working-directory"] == verify["working-directory"] == "${{ github.workspace }}"
        )
