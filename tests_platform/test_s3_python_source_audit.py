from pathlib import Path

import pytest

from tools import provider_gate_source_audit as source_audit
from tools.provider_gate_source_audit import _python_shell_findings
from tools.s3_python_source_audit import s3_python_findings

ROOT = Path(__file__).resolve().parents[1]
SOURCES = (
    "bluefire/s3_access_host_config.py",
    "bluefire/s3_access_setup_cli.py",
    "bluefire/s3_access_runtime.py",
    "bluefire/s3_access_worker_entry.py",
)


@pytest.mark.parametrize("relative", SOURCES)
def test_exact_reviewed_s3_fixed_calls(relative):
    path = ROOT / relative
    assert (
        s3_python_findings(
            relative, path.read_text(encoding="utf-8"), _python_shell_findings(path, ROOT)
        )
        == []
    )


@pytest.mark.parametrize("relative", SOURCES)
@pytest.mark.parametrize("mutation", ("comment", "added_call", "literal"))
def test_any_source_change_needs_review(relative, mutation):
    path = ROOT / relative
    source = path.read_text(encoding="utf-8")
    if mutation == "comment":
        source += "\n# changed\n"
    elif mutation == "added_call":
        source += "\nimportlib.import_module('subprocess')\n"
    else:
        old = (
            "getuid"
            if relative.endswith(("host_config.py", "setup_cli.py"))
            else "bluefire.s3_access_"
        )
        assert old in source
        source = source.replace(old, "changed_literal", 1)
    findings = _python_shell_findings(path, ROOT)
    assert (
        s3_python_findings(relative, source, findings)[-1]["kind"] == "reviewed_s3_source_mismatch"
    )


@pytest.mark.parametrize("relative", SOURCES)
@pytest.mark.parametrize("mutation", ("missing", "extra", "line"))
def test_finding_set_must_be_exact(relative, mutation):
    path = ROOT / relative
    findings = _python_shell_findings(path, ROOT)
    if mutation == "missing":
        findings.pop()
    elif mutation == "extra":
        findings.append({"path": relative, "kind": "unexpected"})
    else:
        findings[0]["line"] += 1
    result = s3_python_findings(relative, path.read_text(encoding="utf-8"), findings)
    assert result[-1]["kind"] == "reviewed_s3_source_mismatch"


def test_unreviewed_dynamic_import_is_not_exempt(tmp_path):
    path = tmp_path / "other.py"
    path.write_text("import importlib\nimportlib.import_module('subprocess')\n", encoding="utf-8")
    findings = _python_shell_findings(path, tmp_path)
    assert findings
    assert s3_python_findings("other.py", path.read_text(encoding="utf-8"), findings) == findings


@pytest.mark.parametrize(
    "relative",
    [
        "bluefire/s3_fixture_contract.py",
        "bluefire/s3_fixture_send.py",
        "bluefire/s3_fixture_sdk.py",
        "bluefire/s3_access_extension_contract.py",
        "bluefire/s3_access_configuration.py",
        "bluefire/s3_access_extension_store.py",
        "bluefire/s3_access_setup.py",
        "bluefire/s3_access_setup_status.py",
        "bluefire/s3_access_onboarding.py",
        "runner/src/s3_fixture_binding.rs",
        "runner/src/s3_reservation_fixture.rs",
    ],
)
def test_fixture_sources_are_required_not_trusted_exemptions(tmp_path, monkeypatch, relative):
    assert relative in source_audit.SOURCE_AUDIT_PATHS
    assert relative not in source_audit.TRUSTED_PROCESS_BOUNDARY_PATHS
    monkeypatch.setattr(source_audit, "SOURCE_AUDIT_PATHS", (relative,))
    monkeypatch.setattr(source_audit, "_process_boundary_report", lambda _root: {})
    with pytest.raises(FileNotFoundError):
        source_audit._source_audit(tmp_path)
    path = tmp_path / relative
    path.parent.mkdir(parents=True)
    original = (ROOT / relative).read_text(encoding="utf-8")
    path.write_text(original, encoding="utf-8")
    files, findings, _ = source_audit._source_audit(tmp_path)
    assert [row["path"] for row in files] == [relative]
    assert findings == []
    path.write_text(
        original + "\n" + ("import subprocess" if path.suffix == ".py" else "// /bin/sh") + "\n",
        encoding="utf-8",
    )
    assert source_audit._source_audit(tmp_path)[1]
