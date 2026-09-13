"""AST inventory for the fixed receiver's explicit, ownership-preserving constructor."""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any


def receiver_launch_contract(path: Path) -> tuple[bool, list[str]]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    constructors = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and ast.unparse(node.func) == "subprocess.Popen.__init__"
    ]
    inventory = ["subprocess.Popen.__init__"] * len(constructors)
    if len(constructors) != 1:
        return False, inventory
    functions = [
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "_spawn_owned_worker"
    ]
    if len(functions) != 1 or constructors[0] not in list(ast.walk(functions[0])):
        return False, inventory
    call = constructors[0]
    expected_arguments = (
        "process",
        '[str(interpreter), "-I", script, "--parent", str(os.getpid()), "--launch", launch_id]',
    )
    expected_options = {
        "executable": "executable",
        "shell": "False",
        "stdin": "subprocess.PIPE",
        "stdout": "subprocess.PIPE",
        "stderr": "subprocess.DEVNULL",
        "close_fds": "True",
        "pass_fds": "tuple(sorted(set(exec_fds + script_fds)))",
        "start_new_session": "True",
        "env": "environment",
        "bufsize": "0",
    }
    options = {node.arg: ast.dump(node.value) for node in call.keywords}
    passed = (
        len(call.args) == len(expected_arguments)
        and all(
            ast.dump(actual) == ast.dump(ast.parse(expected, mode="eval").body)
            for actual, expected in zip(call.args, expected_arguments, strict=True)
        )
        and len(call.keywords) == len(expected_options)
        and options
        == {
            name: ast.dump(ast.parse(value, mode="eval").body)
            for name, value in expected_options.items()
        }
    )
    # The complete module is independently content-pinned in the ordinary
    # process boundary inventory; these checks disclose its real launch site.
    return passed, inventory


def receiver_boundary(path: Path, findings: list[dict[str, Any]]) -> dict[str, Any]:
    passed, calls = receiver_launch_contract(path)
    imports = sum(item.get("kind") == "shell_import" for item in findings)
    unexpected = [item for item in findings if item.get("kind") != "shell_import"]
    return {
        "passed": passed and imports == 1 and not unexpected,
        "shell_imports": imports,
        "process_calls": calls,
        "unexpected_findings": unexpected,
    }
