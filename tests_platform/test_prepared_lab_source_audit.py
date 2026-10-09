"""Fixed startup owners stay in the ordinary exact source and process inventory."""

from __future__ import annotations

from pathlib import Path

import pytest

from tools.prepared_lab_source_audit import BOUNDARIES, prepared_lab_boundary
from tools.provider_gate_source_audit import (
    _REVIEWED_PYTHON_PROCESS_BOUNDARY_SOURCES,
    _process_boundary_report,
    _python_shell_findings,
    _reviewed_python_process_boundary_sources,
)

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def sources():
    return {
        name: (ROOT / name).read_text(encoding="utf-8")
        for name in _REVIEWED_PYTHON_PROCESS_BOUNDARY_SOURCES
    }


def test_registered_fixed_startup_and_transport_sources_pass_existing_audit(sources):
    assert _reviewed_python_process_boundary_sources(sources)
    result = _process_boundary_report(ROOT)
    assert result["passed"]
    assert all(result["python_boundaries"][name]["passed"] for name in BOUNDARIES)


@pytest.mark.parametrize("name", tuple(BOUNDARIES))
def test_every_new_fixed_boundary_refuses_unreviewed_source_changes(sources, name):
    changed = dict(sources)
    changed["bluefire/" + name] += "\n# changed source identity\n"
    assert not _reviewed_python_process_boundary_sources(changed)


def test_ui_descriptor_inheritance_cannot_expand_even_if_call_count_stays_same(tmp_path):
    name = "prepared_lab_ui_bootstrap.py"
    path = tmp_path / name
    path.write_text(
        (ROOT / "bluefire" / name)
        .read_text()
        .replace("pass_fds=(child.fileno(),)", "pass_fds=(child.fileno(), inference.fileno())")
    )
    assert not prepared_lab_boundary(path, _python_shell_findings(path, tmp_path))["passed"]


def test_only_exact_moved_public_lab_path_is_classified():
    from bluefire.release_readiness_gate import _has_private_source_path

    public = "/".join(("", "home", "bluefire"))
    assert not _has_private_source_path(
        "bluefire/prepared_lab_runtime.py", 'HOME = Path("' + public + '")'
    )
    assert _has_private_source_path("bluefire/unrelated.py", public)
    assert _has_private_source_path("bluefire/prepared_lab_runtime.py", public + "-personal")


@pytest.mark.parametrize(
    ("original", "replacement"),
    (
        ("shell=False", "shell=True"),
        ("close_fds=True", "close_fds=False"),
        ("pass_fds=(child.fileno(), listener.fileno())", "pass_fds=(child.fileno(),)"),
        ("--reuid=1002", "--reuid=0"),
        ("bluefire.file_access_probe", "bluefire.unreviewed_worker"),
        ("stdin=subprocess.DEVNULL", "stdin=subprocess.PIPE"),
        ("env=ENV", "env=os.environ"),
    ),
)
def test_fixed_probe_launch_cannot_expand_with_unchanged_process_count(
    tmp_path, original, replacement
):
    name = "prepared_lab_file_access.py"
    path = tmp_path / name
    source = (ROOT / "bluefire" / name).read_text(encoding="utf-8")
    assert source.count(original) == 1
    path.write_text(source.replace(original, replacement), encoding="utf-8")
    assert not prepared_lab_boundary(path, _python_shell_findings(path, tmp_path))["passed"]
