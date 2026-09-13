"""The extracted native responsibilities remain visible to existing source gates."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from bluefire import architecture_gate
from tools.provider_gate_source_audit import _native_command_source_inventory_is_fixed

REPOSITORY = Path(__file__).resolve().parents[1]
CHILDREN = {
    "runner/src/actions/collection.rs": "action",
    "runner/src/safety/cleanup_unix.rs": "safety",
    "runner/src/safety/cleanup_windows.rs": "safety",
}


def test_native_responsibilities_fit_unchanged_caps_and_are_all_audited() -> None:
    report = architecture_gate.audit_repository(REPOSITORY)
    assert report["checks"]["rust_decomposition"] == {"passed": True, "findings": []}
    rows = {row["path"]: row for row in report["size_budget"]["files"]}
    for name, maximum in [("runner/src/actions.rs", 4400), ("runner/src/safety.rs", 2400)]:
        assert rows[name]["lines"] <= maximum
        assert rows[name]["exception_applied"] is True
        policy = json.loads((REPOSITORY / "bluefire/data/architecture_policy.json").read_text())
        budgets = {item["path"]: item["max_lines"] for item in policy["line_budgets"]["exceptions"]}
        assert budgets[name] == maximum
    for name, layer in CHILDREN.items():
        assert rows[name]["lines"] <= 1000
        assert report["dependencies"]["rust"]["layers"][Path(name).stem] == layer
    assert _native_command_source_inventory_is_fixed(REPOSITORY)


@pytest.mark.parametrize("module", [Path(name).stem for name in CHILDREN])
def test_extracted_native_source_without_layer_registration_is_refused(module: str) -> None:
    policy = json.loads((REPOSITORY / "bluefire/data/architecture_policy.json").read_text())
    del policy["rust_layers"][module]
    paths = architecture_gate._source_paths(REPOSITORY, policy)
    report = architecture_gate._dependency_audit(REPOSITORY, policy, paths)
    assert {"code": "rust_module_layer_unclassified", "module": module} in report["findings"]
    assert not report["direction_passed"]


@pytest.mark.parametrize("relative", CHILDREN)
def test_extracted_native_source_cannot_add_an_unreviewed_process_boundary(
    tmp_path: Path, relative: str
) -> None:
    source = tmp_path / "runner/src"
    shutil.copytree(REPOSITORY / "runner/src", source)
    assert _native_command_source_inventory_is_fixed(tmp_path)
    child = tmp_path / relative
    with child.open("a", encoding="utf-8") as output:
        output.write(
            '\nfn unreviewed_process() { let _ = std::process::Command::new("caller"); }\n'
        )
    assert not _native_command_source_inventory_is_fixed(tmp_path)
