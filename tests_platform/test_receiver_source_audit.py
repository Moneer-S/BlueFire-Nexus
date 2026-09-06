"""Static checks only: disclose and pin the exact fixed receiver launch boundary."""

from pathlib import Path

import pytest

from tools import provider_gate_source_audit as audit
from tools.receiver_session_source_audit import receiver_launch_contract

REPOSITORY = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize(
    "before,after",
    [
        ("shell=False", "shell=True"),
        ('"-I"', '"-c"'),
        ('"--launch", launch_id', '"--launch", str(command)'),
        ("executable=executable", "executable=command"),
        ("env=environment", "env=os.environ"),
        ("close_fds=True", "close_fds=False"),
    ],
)
def test_receiver_constructor_inventory_rejects_launch_grammar_changes(tmp_path, before, after):
    path = REPOSITORY / "bluefire/receiver_session.py"
    assert receiver_launch_contract(path) == (True, ["subprocess.Popen.__init__"])
    source = path.read_text(encoding="utf-8")
    assert before in source
    changed = tmp_path / "receiver_session.py"
    changed.write_text(source.replace(before, after, 1), encoding="utf-8")
    passed, calls = receiver_launch_contract(changed)
    assert not passed and calls == ["subprocess.Popen.__init__"]


def test_owner_and_worker_are_fully_pinned_and_report_the_real_constructor():
    sources = {
        name: (REPOSITORY / name).read_text(encoding="utf-8")
        for name in audit._REVIEWED_PYTHON_PROCESS_BOUNDARY_SOURCES
    }
    assert audit._reviewed_python_process_boundary_sources(sources)
    report = audit._process_boundary_report(REPOSITORY)
    assert report["python_boundaries"]["receiver_session.py"] == {
        "passed": True,
        "shell_imports": 1,
        "process_calls": ["subprocess.Popen.__init__"],
        "unexpected_findings": [],
    }
    assert report["python_boundaries"]["receiver_session_worker.py"] == {
        "passed": True,
        "shell_imports": 0,
        "process_calls": [],
        "unexpected_findings": [],
    }
    for relative in ("bluefire/receiver_session.py", "bluefire/receiver_session_worker.py"):
        changed = dict(sources)
        changed[relative] += "\n# Unreviewed owner or worker modification.\n"
        assert not audit._reviewed_python_process_boundary_sources(changed)
