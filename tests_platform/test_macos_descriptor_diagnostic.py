"""Bounded descriptor observations are never startup authority."""

import ast
import json
import os
import stat
from pathlib import Path

from bluefire import macos_file_access_worker, runner_client
from bluefire import macos_setup_failure_diagnostics as diagnostics
from tools import verify_macos_file_access_lifecycle as verifier


def _identity(fd):
    details = os.fstat(fd)
    return {
        "dev": details.st_dev,
        "ino": details.st_ino,
        "mode_type": stat.S_IFMT(details.st_mode),
        "rdev": getattr(details, "st_rdev", 0),
    }


def _frame(rows):
    return (
        json.dumps({"schema_version": diagnostics.NATIVE_FD_ROWS_SCHEMA, "rows": rows}) + "\n"
    ).encode()


def _native_rows():
    identity = {"dev": 1, "ino": 2, "mode_type": stat.S_IFREG, "rdev": 0}
    return [
        {"fd": fd, "kind": 1 if fd != 4 else 2, "identity": identity} for fd in (0, 1, 2, 3, 4, 9)
    ]


def test_worker_failure_site_pin_covers_reviewed_start_method_exactly():
    source = Path(macos_file_access_worker.__file__).read_text(encoding="utf-8")
    module = ast.parse(source)
    owner = next(
        node
        for node in module.body
        if isinstance(node, ast.ClassDef) and node.name == "MacOSFileAccessWorker"
    )
    start = next(
        node for node in owner.body if isinstance(node, ast.FunctionDef) and node.name == "start"
    )
    assert start.end_lineno - start.lineno == diagnostics.MAX_NAMESPACE_OFFSET == 166


def test_worker_owned_duplicate_identity_is_recorded_without_proving_child_inheritance():
    resource, channel = os.pipe()
    sink = []
    observed = []
    try:
        resources = runner_client._prepare_darwin_launch_resources(
            ["fixed-runner"],
            {
                "pass_fds": (resource, channel),
                "_bluefire_descriptor_roles": {
                    resource: "resource",
                    channel: "primitive_channel",
                },
                "_bluefire_descriptor_observation_sink": observed,
            },
            sink,
        )
        assert sink == [resources]
        assert [row["role"] for row in observed] == [
            "resource",
            "primitive_channel",
        ]
        for source, row in zip((resource, channel), observed, strict=True):
            assert row["fd"] != source
            assert row["identity"] == _identity(source) == _identity(row["fd"])
        resources.close()
        for row in observed:
            try:
                os.fstat(row["fd"])
            except OSError:
                pass
            else:
                raise AssertionError("worker-owned duplicate remained open")
    finally:
        os.close(resource)
        os.close(channel)


def test_only_one_exact_native_frame_can_extend_code_96_diagnostic():
    rows = _native_rows()
    parsed = diagnostics.native_fd_rows_from_frame(_frame(rows))
    assert parsed == rows
    observation = {
        "schema_version": diagnostics.NATIVE_FD_OBSERVATION_SCHEMA,
        "scope": "diagnostic_only_no_descriptor_admission",
        "launch_copy_rows": [
            {"role": "resource", "fd": 8, "identity": rows[0]["identity"]},
            {"role": "primitive_channel", "fd": 10, "identity": rows[0]["identity"]},
        ],
        "native_rows": parsed,
    }
    status = {
        "status": "reserved_stage_exit",
        "returncode": 96,
        "label": "initial_descriptor_inventory_unexpected_rows",
        "descriptor_observation": observation,
    }
    assert diagnostics.valid_native_startup_status(status)
    assert verifier._safe_native_startup_statuses({"reader": status}) == {"reader": status}
    assert not diagnostics.valid_native_startup_status({**status, "returncode": 95})
    assert not diagnostics.valid_native_fd_observation({**observation, "scope": "proof"})
    assert diagnostics.native_fd_rows_from_frame(_frame(rows) + b"other\n") is None
    assert diagnostics.native_fd_rows_from_frame(b"x" * 4097) is None
    assert (
        diagnostics.native_fd_rows_from_frame(
            b'{"schema_version":"bluefire.macos-native-fd-rows.v1","rows":[],"rows":[]}\n'
        )
        is None
    )
    assert (
        diagnostics.native_fd_rows_from_frame(_frame([{**rows[0], "path": "/private"}] + rows[1:]))
        is None
    )
