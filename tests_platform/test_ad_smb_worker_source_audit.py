"""No process execution: fail closed on changes to the reviewed AD worker boundary."""

from pathlib import Path

import pytest

from tools import provider_gate_source_audit as audit
from tools.ad_smb_worker_source_audit import ad_worker_boundary, ad_worker_launch_contract

ROOT = Path(__file__).resolve().parents[1]
RELATIVE = "bluefire/ad_smb_worker_process.py"


@pytest.mark.parametrize(
    "relative",
    [
        "bluefire/ad_smb_admitted_transport.py",
        "bluefire/ad_smb_installed.py",
        "bluefire/ad_smb_workspace_results.py",
        "bluefire/ad_smb_receiver_entry.py",
        "bluefire/ad_smb_receiver.py",
        "bluefire/ad_smb_receiver_results.py",
        "bluefire/ad_smb_native_member_results.py",
        "bluefire/ad_smb_worker_wire.py",
        "bluefire/ad_smb_credentials.py",
        "bluefire/ad_smb_native_results.py",
    ],
)
def test_receiver_helpers_remain_strict_no_shell_sources(tmp_path, relative):
    assert relative in audit.SOURCE_AUDIT_PATHS
    assert relative not in audit.TRUSTED_PROCESS_BOUNDARY_PATHS
    source = (ROOT / relative).read_text(encoding="utf-8")
    candidate = tmp_path / Path(relative).name
    candidate.write_text(source, encoding="utf-8")
    assert not audit._python_shell_findings(candidate, tmp_path)
    candidate.write_text(source + "\nimport subprocess\n", encoding="utf-8")
    assert audit._python_shell_findings(candidate, tmp_path)


@pytest.mark.parametrize(
    "before,after",
    [
        ('[executable, "ad-smb-worker"]', "[executable, command]"),
        ('[executable, "ad-smb-worker"]', '[runner_binary, "ad-smb-worker"]'),
        ("shell=False", "shell=True"),
        ("env=environment", "env=os.environ"),
        ("cwd=root", "cwd=work_root"),
        ("close_fds=True", "close_fds=False"),
        ("stdin=subprocess.PIPE", "stdin=None"),
        ("stdout=subprocess.PIPE", "stdout=None"),
        ("stderr=subprocess.PIPE", "stderr=subprocess.DEVNULL"),
        ('getattr(subprocess, "CREATE_SUSPENDED", 0x00000004)', "0"),
    ],
)
def test_ad_worker_launch_grammar_mutations_are_refused(tmp_path, before, after):
    source = (ROOT / RELATIVE).read_text(encoding="utf-8")
    assert ad_worker_launch_contract(ROOT / RELATIVE) == (True, ["subprocess.Popen"])
    assert before in source
    changed = tmp_path / "worker.py"
    changed.write_text(source.replace(before, after, 1), encoding="utf-8")
    assert ad_worker_launch_contract(changed) == (False, ["subprocess.Popen"])


@pytest.mark.parametrize(
    "suffix",
    ["\nsubprocess.Popen(['unexpected'])\n", "\nimport os\nos.system('unexpected')\n"],
)
def test_additional_process_sites_are_not_hidden_by_boundary_registration(tmp_path, suffix):
    changed = tmp_path / "worker.py"
    changed.write_text((ROOT / RELATIVE).read_text(encoding="utf-8") + suffix, encoding="utf-8")
    findings = audit._python_shell_findings(changed, tmp_path)
    assert not ad_worker_boundary(changed, findings)["passed"]


def test_reviewed_worker_is_fully_pinned_and_disclosed():
    texts = {
        name: (ROOT / name).read_text(encoding="utf-8")
        for name in audit._REVIEWED_PYTHON_PROCESS_BOUNDARY_SOURCES
    }
    assert audit._trusted_process_boundary_inventory_is_fixed()
    assert audit._reviewed_python_process_boundary_sources(texts)
    report = audit._process_boundary_report(ROOT)
    assert report["passed"]
    assert report["python_boundaries"]["ad_smb_worker_process.py"] == {
        "passed": True,
        "shell_imports": 1,
        "process_calls": ["subprocess.Popen"],
        "unexpected_findings": [],
    }
    for before, after in [
        ("admit()", "pass"),
        ("containment.assign(job, process)", "pass"),
        ("containment.resume_suspended(process)", "pass"),
        ("_pinned_launch_file(runner_binary, runner_digest)", "unreviewed_launch()"),
        ("containment.terminate(process)", "True"),
        ("revalidate_original,", "lambda: None,"),
    ]:
        assert before in texts[RELATIVE]
        changed = dict(texts)
        changed[RELATIVE] = texts[RELATIVE].replace(before, after, 1)
        assert not audit._reviewed_python_process_boundary_sources(changed)
    texts.pop(RELATIVE)
    assert not audit._reviewed_python_process_boundary_sources(texts)
