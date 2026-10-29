"""Pure validation of one diagnostic FD slot at native run entry."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from bluefire import macos_setup_failure_diagnostics as diagnostics
from tools import verify_macos_file_access_lifecycle as verifier


def _entry(status="present", cloexec=False):
    value = {"phase": diagnostics.NATIVE_RUN_ENTRY_FD3_PHASE, "fd": 3, "status": status}
    if status == "present":
        value.update(
            cloexec=cloexec,
            identity={"dev": 2**32 - 1, "ino": 2**64 - 1, "mode_type": 0o170000, "rdev": 2**32 - 1},
        )
    return value


def _document(entry=None):
    identity = {"dev": 2**64 - 1, "ino": 2**64 - 1, "mode_type": 0o170000, "rdev": 2**64 - 1}
    value = {
        "schema_version": diagnostics.NATIVE_FD_ROWS_SCHEMA,
        "rows": [
            {"fd": 2**31 - 1 - index, "kind": 2**32 - 1, "identity": identity}
            for index in range(diagnostics.MAX_NATIVE_FD_ROWS)
        ],
    }
    if entry is not None:
        value["native_run_entry_fd3"] = entry
    return value


def _frame(document):
    return (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")


def _observation(document):
    value = {
        "schema_version": diagnostics.NATIVE_FD_OBSERVATION_SCHEMA,
        "scope": "diagnostic_only_no_descriptor_admission",
        "launch_copy_rows": [
            {"role": "resource", "fd": 26, "identity": document["rows"][0]["identity"]},
            {"role": "primitive_channel", "fd": 27, "identity": document["rows"][0]["identity"]},
        ],
        "native_rows": document["rows"],
    }
    if "native_run_entry_fd3" in document:
        value["native_run_entry_fd3"] = document["native_run_entry_fd3"]
    return value


@pytest.mark.parametrize(
    "entry", [None, _entry("absent"), _entry("query_error"), _entry(), _entry(cloexec=True)]
)
def test_legacy_and_entry_variants_cross_both_strict_status_validators(entry):
    document = _document(entry)
    raw = _frame(document)
    assert diagnostics.native_fd_diagnostics_from_frame(raw) == (document["rows"], entry)
    assert diagnostics.native_fd_rows_from_frame(raw) == document["rows"]
    observation = _observation(document)
    status = {
        **diagnostics.native_startup_status_from_returncode(96),
        "descriptor_observation": observation,
    }
    assert diagnostics.valid_native_fd_observation(observation)
    assert diagnostics.valid_native_startup_status(status)
    assert verifier._safe_native_startup_statuses({"reader": status}) == {"reader": status}
    for code in (0, 95, 97):
        invalid = {
            **diagnostics.native_startup_status_from_returncode(code),
            "descriptor_observation": observation,
        }
        assert not diagnostics.valid_native_startup_status(invalid)
        assert verifier._safe_native_startup_statuses({"reader": invalid}) is None


def _invalid_entries():
    for field, values in (
        ("phase", (None, True, "exec_entry", "loader_entry")),
        ("fd", (True, 3.0, 4, -1)),
        ("status", (None, True, "unknown", "inherited")),
        ("cloexec", (None, 0, 1, "false")),
        ("identity", (None, [], {"dev": 1})),
    ):
        for value in values:
            yield {**_entry(), field: value}
    for key, invalid in (
        ("dev", -1),
        ("dev", 2**32),
        ("rdev", 2**32),
        ("ino", 2**64),
        ("ino", True),
        ("mode_type", 0o170001),
    ):
        value = _entry()
        value["identity"][key] = invalid
        yield value
    for key in ("phase", "fd", "status", "cloexec", "identity"):
        value = _entry()
        del value[key]
        yield value
    yield {**_entry(), "path": "/private/secret"}
    value = _entry()
    value["identity"]["path"] = "/private/secret"
    yield value
    for status in ("absent", "query_error"):
        yield {**_entry(status), "cloexec": False}
        yield {**_entry(status), "identity": _entry()["identity"]}


@pytest.mark.parametrize("entry", [None, True, [], *_invalid_entries()])
def test_entry_unknown_keys_types_enums_and_widths_are_refused_everywhere(entry):
    assert not diagnostics.valid_native_run_entry_fd3(entry)
    document = _document()
    document["native_run_entry_fd3"] = entry
    assert diagnostics.native_fd_diagnostics_from_frame(_frame(document)) == (None, None)
    assert diagnostics.native_fd_rows_from_frame(_frame(document)) is None
    observation = _observation(document)
    assert not diagnostics.valid_native_fd_observation(observation)
    status = {
        **diagnostics.native_startup_status_from_returncode(96),
        "descriptor_observation": observation,
    }
    assert not diagnostics.valid_native_startup_status(status)
    assert verifier._safe_native_startup_statuses({"reader": status}) is None


def test_entry_normalized_numeric_identity_can_include_zero_fields():
    entry = _entry()
    entry["identity"] = dict.fromkeys(("dev", "ino", "mode_type", "rdev"), 0)
    assert diagnostics.valid_native_run_entry_fd3(entry)
    document = _document(entry)
    assert diagnostics.native_fd_diagnostics_from_frame(_frame(document)) == (
        document["rows"],
        entry,
    )


def test_entry_rejects_duplicate_keys_nonfinite_and_unknown_outer_keys():
    document = _document(_entry())
    raw = _frame(document)
    for invalid in (
        raw.replace(b'"fd":3,', b'"fd":3,"fd":3,', 1),
        raw.replace(b'"cloexec":false', b'"cloexec":NaN', 1),
        _frame({**document, "path": "/private/secret"}),
        raw + b"other\n",
    ):
        assert diagnostics.native_fd_diagnostics_from_frame(invalid) == (None, None)
    observation = _observation(document)
    assert not diagnostics.valid_native_fd_observation({**observation, "path": "/private/secret"})
    status = {
        **diagnostics.native_startup_status_from_returncode(96),
        "native_run_entry_fd3": _entry(),
    }
    assert not diagnostics.valid_native_startup_status(status)
    assert verifier._safe_native_startup_statuses({"reader": status}) is None


def test_maximum_entry_and_legacy_numeric_widths_fit_unchanged_frame_and_capture_caps():
    document = _document(_entry())
    raw = _frame(document)
    # Includes the wider legacy native-row identity domain as a conservative bound.
    assert len(raw) == 2507
    assert len(raw) <= diagnostics.MAX_NATIVE_FD_FRAME_BYTES == 4096
    assert diagnostics.MAX_PREEXEC_FD_FRAME_BYTES == 1024
    assert diagnostics.MAX_COMBINED_FD_FRAME_BYTES == 5120
    assert diagnostics.native_fd_diagnostics_from_frame(raw) == (document["rows"], _entry())
    at_cap = raw[:-1].ljust(diagnostics.MAX_NATIVE_FD_FRAME_BYTES - 1) + b"\n"
    assert diagnostics.native_fd_diagnostics_from_frame(at_cap) == (document["rows"], _entry())
    assert diagnostics.native_fd_diagnostics_from_frame(b" " + at_cap) == (None, None)
    too_many = copy.deepcopy(document)
    too_many["rows"].append(too_many["rows"][0])
    assert diagnostics.native_fd_diagnostics_from_frame(_frame(too_many)) == (None, None)


def test_native_source_samples_only_fixed_fd_before_runtime_checks_and_emits_on_existing_gate():
    source = (
        Path(__file__).resolve().parents[1] / "runner/src/macos_file_access_native.rs"
    ).read_text(encoding="utf-8")
    observe = source.split("    fn observe_native_run_entry_fd3()", 1)[1].split(
        "    pub(super) fn run(", 1
    )[0]
    assert observe.count("libc::fcntl(3, libc::F_GETFD)") == 1
    assert observe.count("libc::fstat(3, &mut details)") == 1
    assert "libc::__error()" in observe and "libc::EBADF" in observe
    assert "flags & libc::FD_CLOEXEC != 0" in observe
    for mutation in (
        "libc::open(",
        "libc::dup(",
        "libc::dup2(",
        "libc::close(",
        "libc::write(",
        "proc_pidinfo(",
    ):
        assert mutation not in observe
    run = source.split("    pub(super) fn run(recipe: super::Recipe", 1)[1]
    body = run.split("{", 1)[1].lstrip()
    assert body.startswith("let entry_fd3 = observe_native_run_entry_fd3();")
    assert (
        body.index("observe_native_run_entry_fd3()")
        < body.index("supported()")
        < body.index("descriptor_inventory(held, channel_fd, None, true, Some(&entry_fd3))")
    )
    assert source.count("emit_initial_descriptor_rows(rows, entry);") == 1
    assert (
        "if initial && checked == Err(super::DescriptorInventoryFailure::UnexpectedRowsPresent) {\n            emit_initial_descriptor_rows(rows, entry);\n        }\n        checked?;"
        in source
    )
    assert "descriptor_inventory(self.held()?, self.channel, self.read_fd, false, None)" in source
