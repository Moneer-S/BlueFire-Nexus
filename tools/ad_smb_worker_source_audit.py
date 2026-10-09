"""Disclose the fixed AD worker launch alongside its complete reviewed source pin."""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any


def ad_worker_launch_contract(path: Path) -> tuple[bool, list[str]]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    launches = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and ast.unparse(node.func) == "subprocess.Popen"
    ]
    inventory = ["subprocess.Popen"] * len(launches)
    functions = [
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "run_worker"
    ]
    if len(launches) != 1 or len(functions) != 1:
        return False, inventory
    call = launches[0]
    if call not in list(ast.walk(functions[0])):
        return False, inventory
    expected_options = {
        "cwd": "root",
        "env": "environment",
        "shell": "False",
        "stdin": "subprocess.PIPE",
        "stdout": "subprocess.PIPE",
        "stderr": "subprocess.PIPE",
        "close_fds": "True",
        "bufsize": "0",
        "creationflags": (
            'getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)'
            ' | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x00000200)'
            ' | getattr(subprocess, "CREATE_SUSPENDED", 0x00000004)'
        ),
    }
    passed = (
        len(call.args) == 1
        and ast.dump(call.args[0])
        == ast.dump(ast.parse('[executable, "ad-smb-worker"]', mode="eval").body)
        and len(call.keywords) == len(expected_options)
        and {node.arg: ast.dump(node.value) for node in call.keywords}
        == {
            name: ast.dump(ast.parse(value, mode="eval").body)
            for name, value in expected_options.items()
        }
    )
    # Full-module content pinning covers admission, executable identity, clean
    # environment, Job assignment before resume, watchdog and terminal cleanup.
    return passed, inventory


def ad_worker_boundary(path: Path, findings: list[dict[str, Any]]) -> dict[str, Any]:
    passed, calls = ad_worker_launch_contract(path)
    imports = sum(item.get("kind") == "shell_import" for item in findings)
    actual_calls = [
        str(item["call"])
        for item in findings
        if item.get("kind") == "dynamic_execution_call" and "call" in item
    ]
    unexpected = [
        item
        for item in findings
        if item.get("kind") not in {"shell_import", "dynamic_execution_call"}
    ]
    return {
        "passed": passed and imports == 1 and actual_calls == calls and not unexpected,
        "shell_imports": imports,
        "process_calls": actual_calls,
        "unexpected_findings": unexpected,
    }
