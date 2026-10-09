from pathlib import Path

import pytest

from tools.provider_gate_source_audit import _python_shell_findings
from tools.s3_python_source_audit import s3_python_findings

ROOT = Path(__file__).resolve().parents[1]
SOURCES = (
    "bluefire/s3_access_host_config.py",
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
        old = "getuid" if relative.endswith("host_config.py") else "bluefire.s3_access_"
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
