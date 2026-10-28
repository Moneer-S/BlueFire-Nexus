"""Inert checks for the bounded helper-side FD observation."""

from __future__ import annotations

import ast
import errno
import os
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest

from bluefire import macos_setup_failure_diagnostics as diagnostics
from tools import verify_macos_file_access_lifecycle as verifier

if os.name != "nt":
    from bluefire import runner_parent_death as helper
else:
    helper = None


def _fake_slots(monkeypatch: pytest.MonkeyPatch, slots: dict[int, tuple[int, int, int, int, bool]]):
    def get_flags(fd: int, operation: int) -> int:
        assert operation == helper.fcntl.F_GETFD
        if fd not in slots:
            raise OSError(errno.EBADF, "closed")
        return helper.fcntl.FD_CLOEXEC if slots[fd][4] else 0

    def get_stat(fd: int) -> SimpleNamespace:
        mode_type, dev, ino, rdev, _cloexec = slots[fd]
        return SimpleNamespace(st_mode=mode_type, st_dev=dev, st_ino=ino, st_rdev=rdev)

    # These modules are shared with pytest and the interpreter. Replace only the
    # helper's references so unrelated fstat calls keep their actual semantics.
    monkeypatch.setattr(
        helper,
        "fcntl",
        SimpleNamespace(**{**vars(helper.fcntl), "fcntl": get_flags}),
    )
    monkeypatch.setattr(helper, "os", SimpleNamespace(**{**vars(helper.os), "fstat": get_stat}))


@pytest.mark.skipif(os.name == "nt", reason="fcntl is unavailable on Windows")
def test_fixed_slot_frame_is_path_free_bounded_and_not_inheritance_proof(monkeypatch):
    _fake_slots(
        monkeypatch,
        {
            0: (stat.S_IFCHR, 1, 2, 3, False),
            2: (stat.S_IFIFO, 1, 4, 0, False),
            3: (stat.S_IFSOCK, -1, 33, 0, False),
            26: (stat.S_IFDIR, 7, 8, 0, True),
        },
    )
    frame = helper._preexec_fd_frame()
    assert frame.startswith(diagnostics.PREEXEC_FD_FRAME_PREFIX)
    assert len(frame) <= diagnostics.MAX_PREEXEC_FD_FRAME_BYTES == 1024
    assert frame.count(b"\n") == 1
    assert b"/private" not in frame and b"secret" not in frame
    observation, reason = diagnostics.preexec_fd_observation_from_frame(frame)
    assert reason is None
    assert observation == {
        "schema_version": diagnostics.PREEXEC_FD_OBSERVATION_SCHEMA,
        "scope": diagnostics.PREEXEC_FD_OBSERVATION_SCOPE,
        "scan_slots": 64,
        "rows": [
            {
                "fd": 0,
                "cloexec": False,
                "identity": {"dev": 1, "ino": 2, "mode_type": stat.S_IFCHR, "rdev": 3},
            },
            {
                "fd": 2,
                "cloexec": False,
                "identity": {"dev": 1, "ino": 4, "mode_type": stat.S_IFIFO, "rdev": 0},
            },
            {
                "fd": 3,
                "cloexec": False,
                "identity": {
                    "dev": 2**32 - 1,
                    "ino": 33,
                    "mode_type": stat.S_IFSOCK,
                    "rdev": 0,
                },
            },
            {
                "fd": 26,
                "cloexec": True,
                "identity": {"dev": 7, "ino": 8, "mode_type": stat.S_IFDIR, "rdev": 0},
            },
        ],
    }
    assert diagnostics.valid_preexec_fd_observation(observation)


@pytest.mark.parametrize(
    "slots,reason",
    [
        ({fd: (stat.S_IFREG, 1, fd, 0, False) for fd in range(16)}, "row_cap"),
        ({0: (stat.S_IFREG, 2**32, 1, 0, False)}, "identity_invalid"),
    ],
)
@pytest.mark.skipif(os.name == "nt", reason="fcntl is unavailable on Windows")
def test_over_row_and_invalid_identity_are_finite_withheld(monkeypatch, slots, reason):
    _fake_slots(monkeypatch, slots)
    frame = helper._preexec_fd_frame()
    assert frame == diagnostics.PREEXEC_FD_FRAME_PREFIX + b"withheld|" + reason.encode() + b"\n"
    assert diagnostics.preexec_fd_observation_from_frame(frame) == (None, reason)


@pytest.mark.skipif(os.name == "nt", reason="fcntl is unavailable on Windows")
def test_query_error_and_byte_cap_are_finite_withheld(monkeypatch):
    def query_error(_fd: int, _operation: int) -> int:
        raise OSError(errno.EIO, "private path or credential text")

    monkeypatch.setattr(
        helper,
        "fcntl",
        SimpleNamespace(**{**vars(helper.fcntl), "fcntl": query_error}),
    )
    assert helper._preexec_fd_frame() == (
        diagnostics.PREEXEC_FD_FRAME_PREFIX + b"withheld|query_error\n"
    )
    _fake_slots(monkeypatch, {0: (stat.S_IFREG, 1, 2, 0, False)})
    monkeypatch.setattr(helper, "_PREEXEC_FD_MAX_FRAME_BYTES", 1)
    assert helper._preexec_fd_frame() == (
        diagnostics.PREEXEC_FD_FRAME_PREFIX + b"withheld|frame_cap\n"
    )


@pytest.mark.parametrize(
    "frame",
    [
        b"bluefire.macos-preexec-fd-rows.v1|slots=65|rows|0,8192,1,2,0,0\n",
        diagnostics.PREEXEC_FD_FRAME_PREFIX + b"rows|\n",
        diagnostics.PREEXEC_FD_FRAME_PREFIX + b"rows|3,49152,1,2,0,0\n",
        diagnostics.PREEXEC_FD_FRAME_PREFIX + b"rows|3,49152,1,2,0,0;3,49152,1,2,0,0\n",
        diagnostics.PREEXEC_FD_FRAME_PREFIX + b"rows|3,49152,1,2,0,0,path\n",
        diagnostics.PREEXEC_FD_FRAME_PREFIX + b"rows|03,49152,1,2,0,0\n",
        diagnostics.PREEXEC_FD_FRAME_PREFIX + b"rows|3,49152,1,2,0,2\n",
        diagnostics.PREEXEC_FD_FRAME_PREFIX + b"withheld|private-path\n",
        diagnostics.PREEXEC_FD_FRAME_PREFIX + b"rows|3,49152,1,2,0,0\nother\n",
        diagnostics.PREEXEC_FD_FRAME_PREFIX + b"x" * 1025,
    ],
)
def test_parser_refuses_unknown_content_and_overlength(frame):
    assert diagnostics.preexec_fd_observation_from_frame(frame) == (None, "invalid_frame")


def test_preexec_observation_is_code_96_only_and_exactly_validated():
    frame = diagnostics.PREEXEC_FD_FRAME_PREFIX + b"rows|2,4096,1,4,0,0;3,49152,1,2,0,0\n"
    observation, reason = diagnostics.preexec_fd_observation_from_frame(frame)
    assert reason is None and observation is not None
    base = diagnostics.native_startup_status_from_returncode(96)
    native_only = {**base, "descriptor_observation_withheld": "no_frame"}
    assert diagnostics.valid_native_startup_status(native_only)
    assert verifier._safe_native_startup_statuses({"reader": native_only}) == {
        "reader": native_only
    }
    status = {**native_only, "preexec_descriptor_observation": observation}
    assert diagnostics.valid_native_startup_status(status)
    assert verifier._safe_native_startup_statuses({"reader": status}) == {"reader": status}
    for invalid in (
        {**status, "returncode": 95},
        {**status, "preexec_descriptor_observation_withheld": "no_frame"},
        {**status, "path": "/private"},
        {**base, "preexec_descriptor_observation": observation},
        {**base, "preexec_descriptor_observation_withheld": "no_frame"},
        {**native_only, "preexec_descriptor_observation": {**observation, "path": "/private"}},
        {**native_only, "preexec_descriptor_observation_withheld": "private-path"},
        {**native_only, "preexec_descriptor_observation_withheld": True},
        {
            "status": "clean_exit",
            "returncode": 0,
            "preexec_descriptor_observation_withheld": "no_frame",
        },
    ):
        assert not diagnostics.valid_native_startup_status(invalid)
        assert verifier._safe_native_startup_statuses({"reader": invalid}) is None


def test_helper_observation_is_after_cloexec_and_before_original_exec():
    source = (
        Path(__file__).resolve().parents[1] / "bluefire" / "runner_parent_death.py"
    ).read_text(encoding="utf-8")
    tree = ast.parse(source)
    function = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "_run_darwin_no_fork_exec"
    )
    calls = [
        (node.lineno, ast.unparse(node.func))
        for node in ast.walk(function)
        if isinstance(node, ast.Call)
    ]
    close_line = next(line for line, name in calls if name == "_close_on_exec")
    observe_line = next(line for line, name in calls if name == "_preexec_fd_frame")
    exec_line = next(line for line, name in calls if name == "os.execve")
    assert close_line < observe_line < exec_line
    assert source.count('target_arguments[1] == "macos-file-access-reader"') == 1
    assignments = {
        node.targets[0].id: node.value.value
        for node in tree.body
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
        and isinstance(node.value, ast.Constant)
    }
    assert assignments["_PREEXEC_FD_SLOTS"] == 64
    assert assignments["_PREEXEC_FD_MAX_ROWS"] == 15
    assert assignments["_PREEXEC_FD_MAX_FRAME_BYTES"] == 1024
