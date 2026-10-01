"""Mocked startup comparisons; no runtime, child, or manager is executed."""

from __future__ import annotations

import ast
import builtins
import errno
import importlib.util
import io
import json
import os
import posixpath
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
SENTINEL = "private-startup-credential-path-sentinel"
FIELDS = (
    "prefix_private",
    "base_prefix_private",
    "stdlib_private",
    "modules_private",
    "executable_matches",
    "libpython_private",
    "old_cache_unmapped",
    "target_fd_closed",
)


def _identity(**changes):
    return dict.fromkeys(FIELDS, True) | changes


def _encoded(**changes):
    return json.dumps(_identity(**changes)).encode()


@pytest.fixture
def runtime():
    spec = importlib.util.spec_from_file_location(
        "ci_startup_comparison_under_test", ROOT / "tools/prepare_ci_python.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def pair(runtime, tmp_path, monkeypatch):
    prefix = tmp_path / SENTINEL
    (prefix / "bin").mkdir(parents=True)
    interpreter = prefix / "bin/python"
    interpreter.write_bytes(b"authored placeholder, never executed")
    state = SimpleNamespace(
        interpreter=interpreter.resolve(),
        prefix=prefix.resolve(),
        root=tmp_path,
        deadline=913.25,
        opened=[],
        closed=[],
        calls=[],
        remaining=[],
        outcomes=[_encoded(), _encoded()],
        mutation=None,
        changed=False,
    )
    nofollow = getattr(os, "O_NOFOLLOW", 1 << 30)
    original_lstat = Path.lstat

    def changed(info):
        return SimpleNamespace(
            **{
                key: getattr(info, key)
                for key in ("st_dev", "st_ino", "st_uid", "st_mode", "st_size")
            },
            st_mtime_ns=info.st_mtime_ns + 1,
        )

    def open_descriptor(path, flags):
        assert path == state.interpreter
        assert flags == os.O_RDONLY | nofollow
        # Only this regular temporary file is opened. The synthetic nofollow
        # flag keeps the helper call observable on Windows, which lacks it.
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0))
        state.opened.append(descriptor)
        return descriptor

    def fstat(descriptor):
        info = os.fstat(descriptor)
        return changed(info) if state.changed and state.mutation[0] == "fd" else info

    def lstat(path, *args, **kwargs):
        info = original_lstat(path, *args, **kwargs)
        target = {"path": state.interpreter, "prefix": state.prefix}.get(
            state.mutation[0] if state.mutation else None
        )
        return changed(info) if state.changed and path == target else info

    def close_descriptor(descriptor):
        assert descriptor in state.opened and descriptor not in state.closed
        state.closed.append(descriptor)
        os.close(descriptor)

    def mutate(phase, count):
        if state.mutation and state.mutation[1:] == (phase, count):
            state.changed = True

    def remaining(deadline):
        state.remaining.append(deadline)
        mutate("before", len(state.remaining))
        return 1.0

    def run(arguments, root, deadline, **options):
        state.calls.append((list(arguments), root, deadline, dict(options)))
        assert len(state.opened) == 1 and state.closed == []
        descriptor = state.opened[0]
        assert os.fstat(descriptor).st_ino == original_lstat(state.interpreter).st_ino
        assert options == {"executable": f"/proc/self/fd/{descriptor}", "pass_fds": (descriptor,)}
        mutate("after", len(state.calls))
        outcome = state.outcomes[len(state.calls) - 1]
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    monkeypatch.setattr(
        runtime,
        "os",
        SimpleNamespace(
            O_RDONLY=os.O_RDONLY,
            O_NOFOLLOW=nofollow,
            open=open_descriptor,
            fstat=fstat,
            close=close_descriptor,
        ),
    )
    monkeypatch.setattr(Path, "lstat", lstat)
    monkeypatch.setattr(runtime, "_remaining", remaining)
    monkeypatch.setattr(runtime, "_run", run)
    try:
        yield state
    finally:
        # Preserve test isolation even if a future helper regression fails the
        # explicit close assertion. This cleanup cannot make that assertion pass.
        for descriptor in state.opened:
            if descriptor not in state.closed:
                try:
                    os.close(descriptor)
                except OSError:
                    pass


def _compare(runtime, pair):
    runtime._startup_comparison(pair.interpreter, pair.prefix, pair.root, pair.deadline)


def _closed(pair):
    assert len(pair.opened) == 1 and pair.closed == pair.opened
    with pytest.raises(OSError) as caught:
        os.fstat(pair.opened[0])
    assert caught.value.errno == errno.EBADF


def _records(capsys):
    captured = capsys.readouterr()
    assert SENTINEL not in captured.out and captured.err == ""
    records = [json.loads(line) for line in captured.out.splitlines()]
    for record in records:
        assert set(record) == {"stage", "argv0", "startup", "identity"}
        assert record["stage"] == "startup_comparison"
        assert record["argv0"] in ("procfd", "canonical")
        assert record["startup"] in ("failed", "completed")
        identity = record["identity"]
        assert identity is None or (
            set(identity) == set(FIELDS) and all(type(v) is bool for v in identity.values())
        )
    return records


def test_result_accepts_only_the_exact_eight_boolean_fields(runtime):
    assert runtime.STARTUP_FIELDS == frozenset(FIELDS)
    assert runtime._startup_result(_encoded(prefix_private=False)) == _identity(
        prefix_private=False
    )


@pytest.mark.parametrize(
    "output",
    (
        b"",
        b"\xff",
        b"[]",
        b"null",
        b"true",
        b'{"error":"maps_limit"}',
        _encoded() + b" trailing",
        json.dumps({key: True for key in FIELDS[1:]}).encode(),
        json.dumps(_identity() | {SENTINEL: True}).encode(),
        _encoded(prefix_private=1),
        _encoded(prefix_private=None),
        _encoded(prefix_private=SENTINEL),
    ),
)
def test_result_rejects_malformed_and_non_boolean_diagnostics(runtime, output, capsys):
    with pytest.raises(runtime.Refusal, match="^startup_probe_output$"):
        runtime._startup_result(output)
    assert capsys.readouterr().out == ""


def test_pair_changes_only_target_argv0_and_reuses_the_held_fd_and_deadline(runtime, pair, capsys):
    _compare(runtime, pair)
    _closed(pair)
    assert len(pair.calls) == 2 and pair.remaining == [pair.deadline, pair.deadline]
    first, second = pair.calls
    assert first[1:] == second[1:] == (pair.root, pair.deadline, first[3])
    assert len(first[0]) == len(second[0])
    assert [
        index
        for index, values in enumerate(zip(first[0], second[0], strict=True))
        if values[0] != values[1]
    ] == [6]
    descriptor = pair.opened[0]
    assert first[0] == [
        str(pair.interpreter),
        "-I",
        "-B",
        "-c",
        runtime.STARTUP_LAUNCHER,
        str(descriptor),
        f"/proc/self/fd/{descriptor}",
        "-I",
        "-B",
        "-c",
        runtime.STARTUP_PROBE,
        str(pair.prefix),
        str(pair.interpreter),
        str(descriptor),
        str(pair.prefix.stat().st_dev),
        str(pair.prefix.stat().st_ino),
    ]
    assert second[0][6] == str(pair.interpreter)
    records = _records(capsys)
    assert [record["argv0"] for record in records] == ["procfd", "canonical"]
    assert all(
        record["startup"] == "completed" and all(record["identity"].values()) for record in records
    )


def test_expired_original_budget_stops_before_any_child_and_closes_fd(
    runtime, pair, capsys, monkeypatch
):
    failure = runtime.Refusal("runtime_deadline")

    def expired(deadline):
        assert deadline == pair.deadline
        raise failure

    monkeypatch.setattr(runtime, "_remaining", expired)
    with pytest.raises(runtime.Refusal) as caught:
        _compare(runtime, pair)
    assert caught.value is failure
    _closed(pair)
    assert pair.calls == [] and _records(capsys) == []


def test_interpreter_outside_selected_prefix_refuses_before_open(runtime, pair, capsys):
    with pytest.raises(runtime.Refusal, match="^probe_interpreter_escape$"):
        runtime._startup_comparison(pair.interpreter, pair.root / "other", pair.root, pair.deadline)
    assert pair.opened == pair.closed == pair.calls == [] and _records(capsys) == []


@pytest.mark.parametrize("failed_child", (False, True))
def test_procfd_failure_or_misplaced_prefix_is_diagnostic_before_valid_control(
    runtime, pair, capsys, failed_child
):
    pair.outcomes[0] = (
        runtime.Refusal("child_failed") if failed_child else _encoded(prefix_private=False)
    )
    _compare(runtime, pair)
    _closed(pair)
    records = _records(capsys)
    assert len(records) == 2 and records[1]["identity"] == _identity()
    assert records[0]["identity"] == (None if failed_child else _identity(prefix_private=False))
    assert records[0]["startup"] == ("failed" if failed_child else "completed")


@pytest.mark.parametrize(
    "code",
    (
        "child_deadline",
        "runtime_deadline",
        "child_output_limit",
        "child_cleanup_unknown",
        "child_identity",
        "unexpected_refusal",
    ),
)
def test_supervisor_refusals_propagate_unchanged_and_stop_the_pair(runtime, pair, capsys, code):
    failure = runtime.Refusal(code)
    pair.outcomes[0] = failure
    with pytest.raises(runtime.Refusal) as caught:
        _compare(runtime, pair)
    assert caught.value is failure
    _closed(pair)
    assert len(pair.calls) == 1 and _records(capsys) == []


@pytest.mark.parametrize("kind", (OSError, RuntimeError))
def test_unexpected_errors_are_not_converted_into_diagnostic_success(runtime, pair, capsys, kind):
    failure = kind(SENTINEL)
    pair.outcomes[0] = failure
    with pytest.raises(kind) as caught:
        _compare(runtime, pair)
    assert caught.value is failure
    _closed(pair)
    assert len(pair.calls) == 1 and _records(capsys) == []


@pytest.mark.parametrize("field", ("executable_matches", "target_fd_closed"))
def test_completed_procfd_must_prove_exec_and_descriptor_integrity(runtime, pair, capsys, field):
    pair.outcomes[0] = _encoded(**{field: False})
    with pytest.raises(runtime.Refusal, match="^startup_comparison_identity$"):
        _compare(runtime, pair)
    _closed(pair)
    assert len(pair.calls) == 1
    assert _records(capsys)[0]["identity"][field] is False


@pytest.mark.parametrize("failed_child", (False, True))
def test_canonical_control_failure_refuses_after_finite_diagnostics(
    runtime, pair, capsys, failed_child
):
    pair.outcomes[1] = (
        runtime.Refusal("child_failed") if failed_child else _encoded(base_prefix_private=False)
    )
    with pytest.raises(runtime.Refusal, match="^startup_control_failed$"):
        _compare(runtime, pair)
    _closed(pair)
    assert len(pair.calls) == 2
    records = _records(capsys)
    assert records[1]["startup"] == ("failed" if failed_child else "completed")


@pytest.mark.parametrize(
    "output", (b'{"error":"maps_limit"}', b'{"private":"' + SENTINEL.encode() + b'"}')
)
def test_invalid_child_output_is_not_a_reportable_startup_failure(runtime, pair, capsys, output):
    pair.outcomes[0] = output
    with pytest.raises(runtime.Refusal, match="^startup_probe_output$"):
        _compare(runtime, pair)
    _closed(pair)
    assert len(pair.calls) == 1 and _records(capsys) == []


@pytest.mark.parametrize("target", ("fd", "path", "prefix"))
@pytest.mark.parametrize("phase", ("before", "after"))
@pytest.mark.parametrize("variant", (1, 2))
def test_each_variant_rechecks_all_identities_before_and_after_execution(
    runtime, pair, capsys, target, phase, variant
):
    pair.mutation = (target, phase, variant)
    with pytest.raises(runtime.Refusal, match="^probe_identity$"):
        _compare(runtime, pair)
    _closed(pair)
    assert len(pair.calls) == variant - (phase == "before")
    assert len(_records(capsys)) == variant - 1


def _exec_fixed(source, modules, extra):
    tree = ast.parse(source)
    assert {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    } == {"os", "sys"}
    assert not any(isinstance(node, ast.ImportFrom) for node in ast.walk(tree))

    def import_module(name, *args, **kwargs):
        assert name in modules
        return modules[name]

    namespace = {"__builtins__": vars(builtins) | {"__import__": import_module}, **extra}
    exec(compile(tree, "<fixed-startup-stub>", "exec"), namespace)


@pytest.mark.parametrize("argv0", ("/proc/self/fd/71", "/synthetic/runtime/bin/python"))
def test_launcher_closes_inheritance_before_execing_the_same_fd(runtime, argv0):
    events = []
    environment = {"AUTHORED_ENV": SENTINEL}

    def execve(descriptor, arguments, env):
        events.append(("exec", descriptor, arguments, env))

    fake_os = SimpleNamespace(
        set_inheritable=lambda fd, value: events.append(("set", fd, value)),
        get_inheritable=lambda fd: events.append(("get", fd)) or False,
        execve=execve,
        environ=environment,
    )
    arguments = ["-c", "71", argv0, "-I", "-B", "-c", "authored-probe", "argument"]
    _exec_fixed(
        runtime.STARTUP_LAUNCHER, {"os": fake_os, "sys": SimpleNamespace(argv=arguments)}, {}
    )
    assert events[:2] == [("set", 71, False), ("get", 71)]
    assert events[2] == ("exec", 71, arguments[2:], environment)
    assert events[2][3] is not environment


def test_launcher_refuses_when_close_on_exec_was_not_established(runtime):
    calls = []
    fake_os = SimpleNamespace(
        set_inheritable=lambda fd, value: calls.append((fd, value)),
        get_inheritable=lambda fd: True,
        execve=lambda *args: pytest.fail("exec must follow a successful inheritance check"),
        environ={},
    )
    with pytest.raises(AssertionError):
        _exec_fixed(
            runtime.STARTUP_LAUNCHER,
            {"os": fake_os, "sys": SimpleNamespace(argv=["-c", "71", "target"])},
            {},
        )
    assert calls == [(71, False)]


@pytest.mark.parametrize("misplaced", (False, True))
def test_probe_reports_prefix_location_as_booleans_without_raw_metadata(runtime, misplaced):
    prefix = "/synthetic/runtime"
    executable = prefix + "/bin/python"
    own_module = prefix + "/lib/python3.12/os.py"
    libpython = prefix + "/lib/libpython3.12.so"
    rows = []
    reads = []

    def fstat(descriptor):
        assert descriptor == 71
        raise OSError(errno.EBADF, SENTINEL)

    fake_os = SimpleNamespace(
        __file__=own_module,
        fstat=fstat,
        stat=lambda value: SimpleNamespace(st_dev=11, st_ino=22),
        path=SimpleNamespace(
            realpath=lambda value: value,
            isfile=lambda value: value in (own_module, libpython, executable),
            basename=posixpath.basename,
            dirname=posixpath.dirname,
            samefile=lambda left, right: left == "/proc/self/exe" and right == executable,
        ),
    )
    fake_sys = SimpleNamespace(
        argv=["-c", prefix, executable, "71", "11", "22"],
        prefix="/" + SENTINEL if misplaced else prefix,
        base_prefix=prefix,
        modules={"os": fake_os},
        exit=lambda code: pytest.fail("bounded map must not exit"),
    )

    class Maps(io.BytesIO):
        def read(self, maximum):
            reads.append(maximum)
            return super().read(maximum)

    def open_maps(path, mode):
        assert (path, mode) == ("/proc/self/maps", "rb")
        return Maps(("0-1 r-xp 0000 00:00 1 " + libpython + "\n").encode())

    _exec_fixed(
        runtime.STARTUP_PROBE,
        {"os": fake_os, "sys": fake_sys},
        {"open": open_maps, "print": rows.append},
    )
    assert reads == [2 * 1024 * 1024 + 1] and len(rows) == 1
    assert SENTINEL not in rows[0] and prefix not in rows[0]
    assert runtime._startup_result(rows[0].encode()) == _identity(prefix_private=not misplaced)
