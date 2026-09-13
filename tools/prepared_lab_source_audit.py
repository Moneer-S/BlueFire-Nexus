"""Disclose real fixed lab/process launch sites; complete sources are content-pinned."""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

# Existing preparation and direct HTTP boundaries are included because the new
# fixed broker uses them. This registers the actual path, without an exemption.
BOUNDARIES = {
    "ai_transport.py": (1, ("subprocess.Popen",)),
    "_ai_transport_worker.py": (0, ()),
    "prepared_lab.py": (1, ("subprocess.Popen",) * 2 + ("subprocess.run",) * 4),
    "prepared_lab_guest.py": (
        2,
        ("os.execve",) * 2 + ("subprocess.Popen",) * 2 + ("subprocess.run",) * 2,
    ),
    "prepared_lab_runtime.py": (1, ("subprocess.run",) * 5),
    "prepared_lab_install.py": (1, ("subprocess.run",) * 7),
    "prepared_lab_broker.py": (1, ("os.execve",) * 3 + ("subprocess.Popen.__init__",)),
    "prepared_lab_ui_bootstrap.py": (1, ("subprocess.Popen.__init__",)),
    "prepared_lab_product.py": (0, ()),
}


def prepared_lab_boundary(path: Path, findings: list[dict[str, Any]]) -> dict[str, Any]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    constructors = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and ast.unparse(node.func) == "subprocess.Popen.__init__"
    ]
    actual = [
        str(item["call"]) for item in findings if item.get("kind") == "dynamic_execution_call"
    ]
    actual.extend("subprocess.Popen.__init__" for _ in constructors)
    imports = sum(item.get("kind") == "shell_import" for item in findings)
    unexpected = [
        item
        for item in findings
        if item.get("kind") not in {"shell_import", "dynamic_execution_call"}
    ]
    expected_imports, expected_calls = BOUNDARIES[path.name]
    constructor_options = all(
        {key.arg: ast.unparse(key.value) for key in node.keywords}.get("shell") == "False"
        and {key.arg: ast.unparse(key.value) for key in node.keywords}.get("close_fds") == "True"
        and {key.arg: ast.unparse(key.value) for key in node.keywords}.get("pass_fds")
        in {"(endpoint.fileno(),)", "(child.fileno(),)"}
        and len(node.args) == 2
        for node in constructors
    )
    return {
        "passed": imports == expected_imports
        and sorted(actual) == sorted(expected_calls)
        and not unexpected
        and constructor_options,
        "shell_imports": imports,
        "process_calls": sorted(actual),
        "unexpected_findings": unexpected,
    }
