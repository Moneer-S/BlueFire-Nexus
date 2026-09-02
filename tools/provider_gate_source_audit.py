"""Static process-boundary and source auditing for provider acceptance."""

from __future__ import annotations

import ast
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from tools.provider_gate_common import (
    PYTHON_DYNAMIC_IMPORT_CALLS,
    PYTHON_DYNAMIC_NAMESPACE_CALLS,
    PYTHON_SHELL_CALLS,
    PYTHON_SHELL_MODULES,
    RUST_SHELL_TOKENS,
    SOURCE_AUDIT_PATHS,
    TRUSTED_PROCESS_BOUNDARY_PATHS,
    ProviderGateError,
    _sha256_bytes,
)

_REVIEWED_RUNNER_CLIENT_LAUNCH_SECTIONS = {
    "SubprocessRustRunner._cancel_darwin_process_slot": "sha256:dac859adb4f10a687d7d2672493ab0cc07f2ea7042856f0668dc5744df1f404b",
    "SubprocessRustRunner._construct_registered_darwin_popen": "sha256:7db01e65689431422cb5c8f2771e2e2b6df795bc20f5773e90193ecd275e0df8",
    "SubprocessRustRunner._quarantine_interrupted_darwin_launch": "sha256:68ec6b976a0a4026733bd428437b9f5ebdc73d34d146a8b8f2913d6ef430936b",
    "SubprocessRustRunner._register_darwin_process_slot": "sha256:1bc9ee71fbd72059c438dd0dcd1604025e0cd6f29084607e9071e48678fcea11",
    "SubprocessRustRunner._reserve_darwin_process_slot": "sha256:7299982185e62363748fdd6fad39554beb15d0d0ddfe79929df396d44801a323",
    "SubprocessRustRunner._retain_indeterminate_darwin_process": "sha256:f3c2dc73f04827716637077d70f966b9b8c1314074c82e4bf713fbe202174210",
    "SubprocessRustRunner._spawn_darwin_no_fork_exec": "sha256:a81df4658a84a3acc2521f1f1e3fd989c424708ef59d4ac82dd512eccb94adc6",
    "SubprocessRustRunner._spawn_darwin_parent_death": "sha256:2c0f510246d5b36067dda8510331ad8a4b6d19d1157dc50faae00207cafe0c77",
    "SubprocessRustRunner._spawn_registered_darwin_popen": "sha256:160aa77b5a1987bf46570b64f14233e21213cb70d9e5fd65893df9416110df19",
    "_DarwinLaunchRequest": "sha256:5c6287a21c1fcd623a85cd5ffea722eb822801eef25d450fe9f77faee5374370",
    "_DarwinLaunchResources": "sha256:4570ecc6ce3fc43024dcdfe12085e05ce9952cda7099fff9d313cdb81dcb0881",
    "_clone_darwin_launch_link": "sha256:8d329eb489bb3ce28e5b6d73ae24c2a4a30013263e687be360f23f356708f300",
    "_duplicate_darwin_descriptor": "sha256:d4d53bd37f3721dec052f5a74e7e1eec78806aac24737bd5f3efef9e62edac14",
    "_execute_darwin_launch_request": "sha256:eea27e653fb8b39b56e4c2bf1311e287d2d4afac4326badb82403978479d0752",
    "_prepare_darwin_launch_resources": "sha256:5277cfbecd9579a79aa4bb481a243fd759175135872f1ae064a26db8831fcef0",
    "_retire_darwin_launch_resources": "sha256:06120e677062a1b3a31df2a3bdbd63e3a27ff08a5e13a4d544679d36aba84414",
    "_run_darwin_launch_worker": "sha256:378da675e749a543d9e34cf92fbd74131db04161ed5140a045e1436d4454be87",
}
_REVIEWED_RUNNER_CLIENT_SOURCE_SHA256 = (
    "sha256:87ee8ac848811635cb5f8388146eb53afda657ff57636fc49987b23097d47a66"
)
_REVIEWED_DARWIN_CONTAINMENT_SECTIONS = {
    "_validate_macos_launch_parent": "sha256:244beadfd89a4f2e6731109cd100042ba2a1ef8ea40e81bbd98f55211e7ebfb6",
}
_REVIEWED_DARWIN_CONTAINMENT_SOURCE_SHA256 = (
    "sha256:91c3e666833997a4035f2bc868e7d0d81c0ea3ead9f9357dd9e97a8f4c898313"
)
_REVIEWED_PARENT_DEATH_SOURCE_SHA256 = (
    "sha256:7a0443b986e18025a748775e18a3fc6cc539713c2cfbb0cc04cce44e3eb277df"
)
_REVIEWED_PYTHON_PROCESS_BOUNDARY_SOURCES = {
    "bluefire/runner_client.py": "sha256:87ee8ac848811635cb5f8388146eb53afda657ff57636fc49987b23097d47a66",
    "bluefire/runner_bootstrap.py": "sha256:2d2ffffec138fdf76587649170b91cc04d2e5fedb6d1768d85b725c7ba809cdf",
    "bluefire/runner_darwin_containment.py": "sha256:91c3e666833997a4035f2bc868e7d0d81c0ea3ead9f9357dd9e97a8f4c898313",
    "bluefire/runner_lifecycle.py": "sha256:921bf67c429aa71f8c3961954a1a28d9b82bf39c0fc8485cba9ffd9e2f581c7c",
    "bluefire/runner_parent_death.py": "sha256:7a0443b986e18025a748775e18a3fc6cc539713c2cfbb0cc04cce44e3eb277df",
    "bluefire/runner_trust.py": "sha256:d244371ead22c1d6f01ccab3f7c14de194b0da8fcf0eba102afdcb918e023801",
    "bluefire/runner_watchdog.py": "sha256:9e6d4b9e4c4b3d64e17b0b138fc8a1b7910aed48a7849563f15ed8abe3fca542",
}
_REVIEWED_RUST_PROCESS_BOUNDARY_SOURCES = (
    "runner/src/cancellation_witness.rs",
    "runner/src/process.rs",
)


def _ast_qualified_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _ast_qualified_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return ""


def _python_aliases(tree: ast.AST) -> tuple[dict[str, str], dict[str, str]]:
    module_aliases: dict[str, str] = {}
    symbol_aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                local_name = alias.asname or alias.name.partition(".")[0]
                module_aliases[local_name] = alias.name if alias.asname else local_name
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            for alias in node.names:
                local_name = alias.asname or alias.name
                symbol_aliases[local_name] = f"{module}.{alias.name}" if module else alias.name
    return module_aliases, symbol_aliases


def _resolved_python_name(
    node: ast.AST,
    module_aliases: Mapping[str, str],
    symbol_aliases: Mapping[str, str],
) -> str:
    raw_name = _ast_qualified_name(node)
    first, separator, remainder = raw_name.partition(".")
    resolved_name = symbol_aliases.get(raw_name, raw_name)
    if separator and first in module_aliases:
        resolved_name = f"{module_aliases[first]}.{remainder}"
    elif not separator and raw_name in module_aliases:
        resolved_name = module_aliases[raw_name]
    return resolved_name


def _is_dynamic_execution_name(name: str) -> bool:
    leaf = name.rpartition(".")[2]
    return (
        name in {"eval", "exec", "builtins.eval", "builtins.exec"}
        or (name.startswith("subprocess.") and leaf in PYTHON_SHELL_CALLS)
        or (name.startswith("asyncio.subprocess.") and leaf in PYTHON_SHELL_CALLS)
        or name
        in {
            "asyncio.create_subprocess_exec",
            "asyncio.create_subprocess_shell",
        }
        or (
            name.startswith("os.")
            and (leaf in PYTHON_SHELL_CALLS or leaf.startswith("exec") or leaf.startswith("spawn"))
        )
    )


def _sensitive_callable_reference(name: str) -> bool:
    return (
        name in PYTHON_DYNAMIC_IMPORT_CALLS
        or name in PYTHON_SHELL_MODULES
        or name == "os"
        or _is_dynamic_execution_name(name)
    )


def _simple_assignment_targets(node: ast.AST) -> tuple[ast.AST, ...]:
    if isinstance(node, ast.Assign):
        return tuple(node.targets)
    if isinstance(node, (ast.AnnAssign, ast.NamedExpr)):
        return (node.target,)
    return ()


def _assignment_value(node: ast.AST) -> ast.AST | None:
    if isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
        return node.value
    return None


def _keyword_is_literal_false(call: ast.Call, name: str) -> bool:
    values = [keyword.value for keyword in call.keywords if keyword.arg == name]
    return len(values) == 1 and isinstance(values[0], ast.Constant) and values[0].value is False


def _expression_matches(node: ast.AST | None, expression: str) -> bool:
    if node is None:
        return False
    expected = ast.parse(expression, mode="eval")
    return ast.dump(node, include_attributes=False) == ast.dump(
        expected.body,
        include_attributes=False,
    )


def _keyword_expressions_match(
    call: ast.Call,
    expected: tuple[tuple[str | None, str], ...],
) -> bool:
    return [keyword.arg for keyword in call.keywords] == [name for name, _ in expected] and all(
        _expression_matches(keyword.value, expression)
        for keyword, (_, expression) in zip(call.keywords, expected, strict=True)
    )


def _enclosing_function(
    node: ast.AST, parents: Mapping[ast.AST, ast.AST]
) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    current = parents.get(node)
    while current is not None:
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return current
        current = parents.get(current)
    return None


def _fixed_options_mapping(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    *,
    name: str,
    initial_keys: set[str],
    assigned_keys: set[str],
    forwarded_to: tuple[tuple[str, str], ...] = (),
    expected_expansions: int = 1,
) -> bool:
    initializers = [
        node
        for node in ast.walk(function)
        if isinstance(node, ast.AnnAssign)
        and isinstance(node.target, ast.Name)
        and node.target.id == name
    ]
    if len(initializers) != 1 or not isinstance(initializers[0].value, ast.Dict):
        return False
    initial = initializers[0].value
    if any(key is None for key in initial.keys):
        return False
    observed_initial_keys = {
        key.value
        for key in initial.keys
        if isinstance(key, ast.Constant) and isinstance(key.value, str)
    }
    if len(observed_initial_keys) != len(initial.keys) or observed_initial_keys != initial_keys:
        return False

    parents = {
        child: parent for parent in ast.walk(function) for child in ast.iter_child_nodes(parent)
    }
    expansions = 0
    forwards = 0
    observed_assigned_keys: set[str] = set()
    for node in ast.walk(function):
        target: ast.AST | None = None
        if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else (node.target,)
            for candidate in targets:
                if (
                    isinstance(candidate, ast.Subscript)
                    and isinstance(candidate.value, ast.Name)
                    and candidate.value.id == name
                ):
                    target = candidate
                    break
                if (
                    isinstance(candidate, ast.Name)
                    and candidate.id == name
                    and node is not initializers[0]
                ):
                    return False
        if isinstance(target, ast.Subscript):
            key = target.slice
            if not (
                isinstance(key, ast.Constant)
                and isinstance(key.value, str)
                and key.value in assigned_keys
            ):
                return False
            observed_assigned_keys.add(key.value)
        if isinstance(node, ast.Name) and node.id == name and isinstance(node.ctx, ast.Load):
            parent = parents.get(node)
            if isinstance(parent, ast.Subscript) and parent.value is node:
                continue
            if isinstance(parent, ast.keyword) and parent.arg is None:
                expansions += 1
                continue
            if isinstance(parent, ast.keyword):
                owner = parents.get(parent)
                if (
                    isinstance(owner, ast.Call)
                    and (_ast_qualified_name(owner.func), parent.arg) in forwarded_to
                ):
                    forwards += 1
                    continue
            return False
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == name
        ):
            return False
    return (
        expansions == expected_expansions
        and forwards == len(forwarded_to)
        and observed_assigned_keys == assigned_keys
    )


def _copied_options_mapping(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    *,
    name: str,
    source_name: str,
    assigned_keys: set[str],
) -> bool:
    assignments = [
        node
        for node in ast.walk(function)
        if isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr))
        and any(
            isinstance(target, ast.Name) and target.id == name
            for target in _simple_assignment_targets(node)
        )
    ]
    if len(assignments) != 1:
        return False
    initializer = assignments[0]
    targets = _simple_assignment_targets(initializer)
    value = _assignment_value(initializer)
    if (
        len(targets) != 1
        or not isinstance(targets[0], ast.Name)
        or not _expression_matches(value, f"dict({source_name})")
    ):
        return False

    parents = {
        child: parent for parent in ast.walk(function) for child in ast.iter_child_nodes(parent)
    }
    expansions = 0
    observed_assigned_keys: set[str] = set()
    for node in ast.walk(function):
        target: ast.AST | None = None
        if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            candidates = node.targets if isinstance(node, ast.Assign) else (node.target,)
            for candidate in candidates:
                if (
                    isinstance(candidate, ast.Subscript)
                    and isinstance(candidate.value, ast.Name)
                    and candidate.value.id == name
                ):
                    target = candidate
                    break
                if (
                    isinstance(candidate, ast.Name)
                    and candidate.id == name
                    and node is not initializer
                ):
                    return False
        if isinstance(target, ast.Subscript):
            key = target.slice
            if not (
                isinstance(key, ast.Constant)
                and isinstance(key.value, str)
                and key.value in assigned_keys
            ):
                return False
            observed_assigned_keys.add(key.value)
        if isinstance(node, ast.Name) and node.id == name and isinstance(node.ctx, ast.Load):
            parent = parents.get(node)
            if isinstance(parent, ast.Subscript) and parent.value is node:
                continue
            if isinstance(parent, ast.keyword) and parent.arg is None:
                expansions += 1
                continue
            return False

    source_loads = [
        node
        for node in ast.walk(function)
        if isinstance(node, ast.Name) and node.id == source_name and isinstance(node.ctx, ast.Load)
    ]
    return (
        expansions == 1
        and observed_assigned_keys == assigned_keys
        and len(source_loads) == 1
        and isinstance(value, ast.Call)
        and source_loads[0] in value.args
        and _function_parameter_is_unmodified(function, source_name)
    )


def _function_parameter_is_unmodified(
    function: ast.FunctionDef | ast.AsyncFunctionDef, name: str
) -> bool:
    return not any(
        isinstance(node, ast.Name)
        and node.id == name
        and isinstance(node.ctx, (ast.Store, ast.Del))
        for node in ast.walk(function)
    )


def _runner_client_popen_contract(path: Path) -> bool:
    text = path.read_text(encoding="utf-8")
    if _sha256_bytes(text.encode("utf-8")) != _REVIEWED_RUNNER_CLIENT_SOURCE_SHA256:
        return False
    tree = ast.parse(text, filename=path.name)
    lines = text.splitlines()

    def section_digest(node: ast.AST) -> str:
        if not hasattr(node, "lineno") or getattr(node, "end_lineno", None) is None:
            return ""
        decorators = getattr(node, "decorator_list", ())
        start_line = min((node.lineno, *(item.lineno for item in decorators)))  # type: ignore[attr-defined]
        source = "\n".join(lines[start_line - 1 : node.end_lineno]) + "\n"  # type: ignore[attr-defined]
        return _sha256_bytes(source.encode("utf-8"))

    reviewed_sections: dict[str, str] = {}
    reviewed_section_counts: dict[str, int] = {}
    module_sections = {
        "_prepare_darwin_launch_resources",
        "_clone_darwin_launch_link",
        "_duplicate_darwin_descriptor",
        "_run_darwin_launch_worker",
        "_execute_darwin_launch_request",
        "_retire_darwin_launch_resources",
    }
    reviewed_classes = {"_DarwinLaunchRequest", "_DarwinLaunchResources"}
    reviewed_methods = {
        key.partition(".")[2]
        for key in _REVIEWED_RUNNER_CLIENT_LAUNCH_SECTIONS
        if key.startswith("SubprocessRustRunner.")
    }
    if (
        sum(
            isinstance(node, ast.ClassDef) and node.name == "SubprocessRustRunner"
            for node in tree.body
        )
        != 1
    ):
        return False
    for node in tree.body:
        if (
            isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name in module_sections
        ):
            reviewed_sections[node.name] = section_digest(node)
            reviewed_section_counts[node.name] = reviewed_section_counts.get(node.name, 0) + 1
        elif isinstance(node, ast.ClassDef) and node.name in reviewed_classes:
            reviewed_sections[node.name] = section_digest(node)
            reviewed_section_counts[node.name] = reviewed_section_counts.get(node.name, 0) + 1
        elif isinstance(node, ast.ClassDef) and node.name == "SubprocessRustRunner":
            for method in node.body:
                if (
                    isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and method.name in reviewed_methods
                ):
                    key = f"{node.name}.{method.name}"
                    reviewed_sections[key] = section_digest(method)
                    reviewed_section_counts[key] = reviewed_section_counts.get(key, 0) + 1
    if (
        reviewed_sections != _REVIEWED_RUNNER_CLIENT_LAUNCH_SECTIONS
        or set(reviewed_section_counts) != set(_REVIEWED_RUNNER_CLIENT_LAUNCH_SECTIONS)
        or any(count != 1 for count in reviewed_section_counts.values())
    ):
        return False

    protected_module_names = {
        key for key in _REVIEWED_RUNNER_CLIENT_LAUNCH_SECTIONS if "." not in key
    } | {"_validate_darwin_launch_parent"}
    protected_method_names = {
        key.partition(".")[2]
        for key in _REVIEWED_RUNNER_CLIENT_LAUNCH_SECTIONS
        if key.startswith("SubprocessRustRunner.")
    }
    direct_name_rebindings = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Name)
        and node.id in protected_module_names
        and isinstance(node.ctx, (ast.Store, ast.Del))
    ]
    direct_method_rebindings = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Attribute)
        and isinstance(node.ctx, (ast.Store, ast.Del))
        and node.attr in protected_method_names
    ]
    protected_names = protected_module_names | protected_method_names
    protected_string_rebindings = [
        node
        for node in ast.walk(tree)
        if (
            isinstance(node, ast.Call)
            and _ast_qualified_name(node.func).rpartition(".")[2]
            in {"setattr", "delattr", "__setattr__", "__delattr__"}
        )
        or (
            isinstance(node, ast.Subscript)
            and isinstance(node.ctx, (ast.Store, ast.Del))
            and any(
                isinstance(item, ast.Constant) and item.value in protected_names
                for item in ast.walk(node.slice)
            )
        )
    ]
    validator_imports = [
        alias
        for node in tree.body
        if isinstance(node, ast.ImportFrom)
        and node.level == 1
        and node.module == "runner_darwin_containment"
        for alias in node.names
        if alias.asname == "_validate_darwin_launch_parent"
    ]
    if (
        direct_name_rebindings
        or direct_method_rebindings
        or protected_string_rebindings
        or len(validator_imports) != 1
        or validator_imports[0].name != "_validate_macos_launch_parent"
    ):
        return False

    module_aliases, symbol_aliases = _python_aliases(tree)
    calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and _resolved_python_name(node.func, module_aliases, symbol_aliases) == "subprocess.Popen"
    ]
    if len(calls) != 2:
        return False
    parents = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}
    calls_by_function: dict[str, list[ast.Call]] = {}
    functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
    for call in calls:
        function = _enclosing_function(call, parents)
        if function is None:
            return False
        calls_by_function.setdefault(function.name, []).append(call)
        functions[function.name] = function
    if set(calls_by_function) != {"_spawn", "_spawn_linux_parent_death"} or any(
        len(function_calls) != 1 for function_calls in calls_by_function.values()
    ):
        return False

    spawn = functions["_spawn"]
    spawn_call = calls_by_function["_spawn"][0]
    parent_death_calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and _ast_qualified_name(node.func) == "self._spawn_linux_parent_death"
    ]
    darwin_parent_death_calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and _ast_qualified_name(node.func) == "self._spawn_darwin_parent_death"
    ]
    darwin_no_fork_calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and _ast_qualified_name(node.func) == "self._spawn_darwin_no_fork_exec"
    ]
    registered_darwin_calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and _ast_qualified_name(node.func) == "self._spawn_registered_darwin_popen"
    ]
    direct_registered_darwin_calls = [
        call for call in registered_darwin_calls if _enclosing_function(call, parents) is spawn
    ]
    if (
        len(parent_death_calls) != 1
        or _enclosing_function(parent_death_calls[0], parents) is not spawn
        or len(darwin_parent_death_calls) != 1
        or _enclosing_function(darwin_parent_death_calls[0], parents) is not spawn
        or len(darwin_no_fork_calls) != 1
        or _enclosing_function(darwin_no_fork_calls[0], parents) is not spawn
        or len(registered_darwin_calls) != 3
        or len(direct_registered_darwin_calls) != 1
    ):
        return False
    parent_death_forward = parent_death_calls[0]
    darwin_parent_death_forward = darwin_parent_death_calls[0]
    darwin_no_fork_forward = darwin_no_fork_calls[0]
    direct_registered_darwin = direct_registered_darwin_calls[0]
    spawn_valid = (
        len(spawn_call.args) == 1
        and _expression_matches(spawn_call.args[0], "argv")
        and _function_parameter_is_unmodified(spawn, "argv")
        and _keyword_expressions_match(
            spawn_call,
            (
                ("cwd", "self.work_root"),
                ("env", "environment"),
                ("stdin", "subprocess.DEVNULL"),
                ("stdout", "stdout"),
                ("stderr", "stderr"),
                ("shell", "False"),
                (None, "options"),
            ),
        )
        and len(parent_death_forward.args) == 1
        and _expression_matches(parent_death_forward.args[0], "argv")
        and _keyword_expressions_match(
            parent_death_forward,
            (
                ("stdout", "stdout"),
                ("stderr", "stderr"),
                ("environment", "environment"),
                ("inherited_descriptors", "inherited_descriptors"),
                ("options", "options"),
            ),
        )
        and len(darwin_parent_death_forward.args) == 1
        and _expression_matches(darwin_parent_death_forward.args[0], "argv")
        and _keyword_expressions_match(
            darwin_parent_death_forward,
            (
                ("stdout", "stdout"),
                ("stderr", "stderr"),
                ("environment", "environment"),
                ("inherited_descriptors", "inherited_descriptors"),
                ("options", "options"),
                ("darwin_slot", "darwin_slot"),
                ("process_sink", "process_sink"),
            ),
        )
        and len(darwin_no_fork_forward.args) == 1
        and _expression_matches(darwin_no_fork_forward.args[0], "argv")
        and _keyword_expressions_match(
            darwin_no_fork_forward,
            (
                ("stdout", "stdout"),
                ("stderr", "stderr"),
                ("environment", "environment"),
                ("inherited_descriptors", "inherited_descriptors"),
                ("options", "options"),
                ("darwin_slot", "darwin_slot"),
                ("process_sink", "process_sink"),
            ),
        )
        and len(direct_registered_darwin.args) == 3
        and _expression_matches(direct_registered_darwin.args[0], "darwin_slot")
        and _expression_matches(direct_registered_darwin.args[1], "process_sink")
        and _expression_matches(direct_registered_darwin.args[2], "argv")
        and _keyword_expressions_match(
            direct_registered_darwin,
            (
                ("cwd", "self.work_root"),
                ("env", "environment"),
                ("stdin", "subprocess.DEVNULL"),
                ("stdout", "stdout"),
                ("stderr", "stderr"),
                ("shell", "False"),
                (None, "options"),
            ),
        )
        and _fixed_options_mapping(
            spawn,
            name="options",
            initial_keys=set(),
            assigned_keys={
                "creationflags",
                "start_new_session",
                "pass_fds",
                "_bluefire_descriptor_argument_indexes",
            },
            forwarded_to=(
                ("self._spawn_linux_parent_death", "options"),
                ("self._spawn_darwin_parent_death", "options"),
                ("self._spawn_darwin_no_fork_exec", "options"),
            ),
            expected_expansions=2,
        )
    )

    parent_death = functions["_spawn_linux_parent_death"]
    parent_death_call = calls_by_function["_spawn_linux_parent_death"][0]
    parent_death_valid = (
        len(parent_death_call.args) == 1
        and _expression_matches(
            parent_death_call.args[0],
            """[
                interpreter_launch[0],
                "-I",
                "-B",
                "-X",
                "utf8",
                helper_launch[0],
                str(os.getpid()),
                str(child_socket.fileno()),
                str(target_descriptor),
                nonce,
                ",".join(str(value) for value in helper_descriptors),
                *argv,
            ]""",
        )
        and _function_parameter_is_unmodified(parent_death, "argv")
        and _keyword_expressions_match(
            parent_death_call,
            (
                ("cwd", "self.work_root"),
                ("env", "dict(environment)"),
                ("stdin", "subprocess.DEVNULL"),
                ("stdout", "stdout"),
                ("stderr", "stderr"),
                ("shell", "False"),
                (None, "launch_options"),
            ),
        )
        and _copied_options_mapping(
            parent_death,
            name="launch_options",
            source_name="options",
            assigned_keys={"pass_fds"},
        )
    )
    helper_calls = {
        name: [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and _ast_qualified_name(node.func) == name
        ]
        for name in ("spawn_darwin_parent_death", "spawn_darwin_no_fork_exec")
    }
    if any(len(found) != 1 for found in helper_calls.values()):
        return False
    parent_helper_call = helper_calls["spawn_darwin_parent_death"][0]
    no_fork_helper_call = helper_calls["spawn_darwin_no_fork_exec"][0]
    parent_helper = _enclosing_function(parent_helper_call, parents)
    no_fork_helper = _enclosing_function(no_fork_helper_call, parents)
    helper_factories_valid = (
        parent_helper is not None
        and parent_helper.name == "_spawn_darwin_parent_death"
        and len(parent_helper_call.args) == 1
        and _expression_matches(parent_helper_call.args[0], "argv")
        and _keyword_expressions_match(
            parent_helper_call,
            (
                ("stdout", "stdout"),
                ("stderr", "stderr"),
                ("environment", "environment"),
                ("inherited_descriptors", "inherited_descriptors"),
                ("options", "options"),
                ("runner_binary", "self.runner_binary"),
                ("runner_binary_digest", "self.runner_binary_digest"),
                ("work_root", "self.work_root"),
                ("watchdog_interpreter", "self._watchdog_interpreter"),
                ("watchdog_interpreter_digest", "self._watchdog_interpreter_digest"),
                ("parent_death_script", "self.parent_death_script"),
                ("parent_death_script_digest", "self.parent_death_script_digest"),
                ("pinned_launch_file", "_pinned_launch_file"),
                ("start_grace_seconds", "_WATCHDOG_START_GRACE_SECONDS"),
                ("execution_timeout_seconds", "self.timeout_seconds"),
                ("failure_sink", "failed_processes"),
                ("popen_factory", "registered_popen"),
            ),
        )
        and _function_parameter_is_unmodified(parent_helper, "registered_popen")
        and no_fork_helper is not None
        and no_fork_helper.name == "_spawn_darwin_no_fork_exec"
        and len(no_fork_helper_call.args) == 1
        and _expression_matches(no_fork_helper_call.args[0], "argv")
        and _keyword_expressions_match(
            no_fork_helper_call,
            (
                ("stdout", "stdout"),
                ("stderr", "stderr"),
                ("environment", "environment"),
                ("inherited_descriptors", "inherited_descriptors"),
                ("options", "options"),
                ("runner_binary", "self.runner_binary"),
                ("runner_binary_digest", "self.runner_binary_digest"),
                ("work_root", "self.work_root"),
                ("watchdog_interpreter", "self._watchdog_interpreter"),
                ("watchdog_interpreter_digest", "self._watchdog_interpreter_digest"),
                ("parent_death_script", "self.parent_death_script"),
                ("parent_death_script_digest", "self.parent_death_script_digest"),
                ("pinned_launch_file", "_pinned_launch_file"),
                ("start_grace_seconds", "_WATCHDOG_START_GRACE_SECONDS"),
                ("popen_factory", "registered_popen"),
                ("proof_sink", "proven_processes"),
                ("proof_callback", "self._darwin_no_fork_proven.add"),
            ),
        )
        and _function_parameter_is_unmodified(no_fork_helper, "registered_popen")
    )

    nested_registered_calls = [
        call for call in registered_darwin_calls if call is not direct_registered_darwin
    ]
    wrapper_owners: set[str] = set()
    wrappers_valid = len(nested_registered_calls) == 2
    for call in nested_registered_calls:
        wrapper = _enclosing_function(call, parents)
        outer = _enclosing_function(wrapper, parents) if wrapper is not None else None
        if wrapper is None or outer is None:
            wrappers_valid = False
            continue
        wrapper_owners.add(outer.name)
        wrappers_valid = bool(
            wrappers_valid
            and wrapper.name == "registered_popen"
            and len(wrapper.body) == 1
            and isinstance(wrapper.body[0], ast.Return)
            and wrapper.body[0].value is call
            and wrapper.args.kwarg is not None
            and wrapper.args.kwarg.arg == "launch_options"
            and [argument.arg for argument in wrapper.args.args] == ["arguments"]
            and len(call.args) == 3
            and _expression_matches(call.args[0], "darwin_slot")
            and _expression_matches(call.args[1], "process_sink")
            and _expression_matches(call.args[2], "arguments")
            and _keyword_expressions_match(call, ((None, "launch_options"),))
            and _function_parameter_is_unmodified(wrapper, "arguments")
            and _function_parameter_is_unmodified(wrapper, "launch_options")
        )
    wrappers_valid = wrappers_valid and wrapper_owners == {
        "_spawn_darwin_parent_death",
        "_spawn_darwin_no_fork_exec",
    }

    prepare_calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and _ast_qualified_name(node.func) == "_prepare_darwin_launch_resources"
    ]
    request_calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and _ast_qualified_name(node.func) == "_DarwinLaunchRequest"
    ]
    publication_calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and _ast_qualified_name(node.func) == "_DARWIN_LAUNCH_REQUESTS.append"
    ]
    executor_calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and _ast_qualified_name(node.func) == "_execute_darwin_launch_request"
    ]
    executor_loads = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Name)
        and node.id == "_execute_darwin_launch_request"
        and isinstance(node.ctx, ast.Load)
    ]
    prepare_loads = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Name)
        and node.id == "_prepare_darwin_launch_resources"
        and isinstance(node.ctx, ast.Load)
    ]
    ownership_handoff_valid = False
    if (
        len(prepare_calls) == 1
        and len(prepare_loads) == 1
        and len(request_calls) == 1
        and len(publication_calls) == 1
        and len(executor_calls) == 1
        and len(executor_loads) == 1
    ):
        prepare_call = prepare_calls[0]
        request_call = request_calls[0]
        publication_call = publication_calls[0]
        executor_call = executor_calls[0]
        handoff = _enclosing_function(prepare_call, parents)
        executor_owner = _enclosing_function(executor_call, parents)
        prepare_statement = parents.get(prepare_call)
        prepare_start = (
            (prepare_statement.lineno, prepare_statement.col_offset)
            if isinstance(prepare_statement, ast.Assign)
            else (prepare_call.lineno, prepare_call.col_offset)
        )
        resource_names = [
            node
            for node in (ast.walk(handoff) if handoff is not None else ())
            if (
                isinstance(node, ast.Name)
                and node.id == "resources"
                and prepare_start
                <= (node.lineno, node.col_offset)
                < (publication_call.lineno, publication_call.col_offset)
            )
        ]
        resource_stores = [
            node for node in resource_names if isinstance(node.ctx, (ast.Store, ast.Del))
        ]
        resource_loads = [node for node in resource_names if isinstance(node.ctx, ast.Load)]
        request_resource_values = [
            keyword.value for keyword in request_call.keywords if keyword.arg == "resources"
        ]
        request_statement = parents.get(request_call)
        request_start = (
            (request_statement.lineno, request_statement.col_offset)
            if isinstance(request_statement, ast.Assign)
            else (request_call.lineno, request_call.col_offset)
        )
        publication_end = (
            publication_call.end_lineno or publication_call.lineno,
            publication_call.end_col_offset or publication_call.col_offset,
        )
        request_names = [
            node
            for node in (ast.walk(handoff) if handoff is not None else ())
            if (
                isinstance(node, ast.Name)
                and node.id == "request"
                and request_start <= (node.lineno, node.col_offset) <= publication_end
            )
        ]
        request_stores = [
            node for node in request_names if isinstance(node.ctx, (ast.Store, ast.Del))
        ]
        request_loads = [node for node in request_names if isinstance(node.ctx, ast.Load)]
        ownership_handoff_valid = bool(
            handoff is not None
            and handoff.name == "_spawn_registered_darwin_popen"
            and _enclosing_function(request_call, parents) is handoff
            and _enclosing_function(publication_call, parents) is handoff
            and len(prepare_call.args) == 3
            and _expression_matches(prepare_call.args[0], "argv")
            and _expression_matches(prepare_call.args[1], "options")
            and _expression_matches(prepare_call.args[2], "resource_sink")
            and not prepare_call.keywords
            and isinstance(prepare_statement, ast.Assign)
            and prepare_statement.value is prepare_call
            and len(prepare_statement.targets) == 1
            and len(resource_stores) == 1
            and prepare_statement.targets[0] is resource_stores[0]
            and len(resource_loads) == 1
            and request_resource_values == resource_loads
            and isinstance(request_statement, ast.Assign)
            and request_statement.value is request_call
            and len(request_statement.targets) == 1
            and len(request_stores) == 1
            and request_statement.targets[0] is request_stores[0]
            and len(request_loads) == 1
            and not request_call.args
            and _keyword_expressions_match(
                request_call,
                (
                    ("owner", "self"),
                    ("token", "token"),
                    ("process_sink", "process_sink"),
                    ("resources", "resources"),
                ),
            )
            and len(publication_call.args) == 1
            and _expression_matches(publication_call.args[0], "request")
            and publication_call.args[0] is request_loads[0]
            and not publication_call.keywords
            and (prepare_call.lineno, prepare_call.col_offset)
            < (request_call.lineno, request_call.col_offset)
            < (publication_call.lineno, publication_call.col_offset)
            and executor_owner is not None
            and executor_owner.name == "_run_darwin_launch_worker"
            and len(executor_call.args) == 1
            and _expression_matches(executor_call.args[0], "request")
            and not executor_call.keywords
        )

    constructor_calls = {
        name: [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and _resolved_python_name(node.func, module_aliases, symbol_aliases) == name
        ]
        for name in ("subprocess.Popen.__new__", "subprocess.Popen.__init__")
    }
    if any(len(found) != 1 for found in constructor_calls.values()):
        return False
    constructor = _enclosing_function(constructor_calls["subprocess.Popen.__init__"][0], parents)
    new_constructor = _enclosing_function(constructor_calls["subprocess.Popen.__new__"][0], parents)
    new_call = constructor_calls["subprocess.Popen.__new__"][0]
    init_call = constructor_calls["subprocess.Popen.__init__"][0]
    construction_forwards = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and _ast_qualified_name(node.func) == "request.owner._construct_registered_darwin_popen"
    ]
    darwin_constructor_valid = (
        constructor is not None
        and constructor is new_constructor
        and constructor.name == "_construct_registered_darwin_popen"
        and len(new_call.args) == 1
        and _expression_matches(new_call.args[0], "subprocess.Popen")
        and not new_call.keywords
        and len(init_call.args) == 2
        and _expression_matches(init_call.args[0], "process")
        and _expression_matches(init_call.args[1], "argv")
        and _keyword_expressions_match(init_call, ((None, "options"),))
        and _function_parameter_is_unmodified(constructor, "argv")
        and len(construction_forwards) == 1
        and ((worker := _enclosing_function(construction_forwards[0], parents)) is not None)
        and worker.name == "_execute_darwin_launch_request"
        and len(construction_forwards[0].args) == 3
        and _expression_matches(construction_forwards[0].args[0], "request.token")
        and _expression_matches(construction_forwards[0].args[1], "request.process_sink")
        and _expression_matches(construction_forwards[0].args[2], "resources.argv")
        and _keyword_expressions_match(construction_forwards[0], ((None, "resources.options"),))
    )
    return bool(
        spawn_valid
        and parent_death_valid
        and helper_factories_valid
        and wrappers_valid
        and ownership_handoff_valid
        and darwin_constructor_valid
    )


def _runner_lifecycle_popen_contract(path: Path) -> bool:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=path.name)
    module_aliases, symbol_aliases = _python_aliases(tree)
    calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and _resolved_python_name(node.func, module_aliases, symbol_aliases) == "subprocess.Popen"
    ]
    if len(calls) != 1:
        return False
    call = calls[0]
    parents = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}
    function = _enclosing_function(call, parents)
    return (
        function is not None
        and function.name == "_spawn_contained_host"
        and len(call.args) == 1
        and isinstance(call.args[0], ast.Name)
        and call.args[0].id == "command"
        and _function_parameter_is_unmodified(function, "command")
        and [keyword.arg for keyword in call.keywords] == ["shell", None]
        and _keyword_is_literal_false(call, "shell")
        and isinstance(call.keywords[1].value, ast.Name)
        and call.keywords[1].value.id == "options"
        and _fixed_options_mapping(
            function,
            name="options",
            initial_keys={"stdin", "stdout", "stderr", "close_fds"},
            assigned_keys={"creationflags", "start_new_session"},
        )
    )


def _runner_darwin_popen_contract(path: Path) -> bool:
    """Lock both Darwin factory launches to their verified helper grammars."""

    text = path.read_text(encoding="utf-8")
    if _sha256_bytes(text.encode("utf-8")) != _REVIEWED_DARWIN_CONTAINMENT_SOURCE_SHA256:
        return False
    tree = ast.parse(text, filename=path.name)
    lines = text.splitlines()
    reviewed_validators = [
        node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == "_validate_macos_launch_parent"
    ]
    if len(reviewed_validators) != 1:
        return False
    validator = reviewed_validators[0]
    validator_start = min(
        (validator.lineno, *(decorator.lineno for decorator in validator.decorator_list))
    )
    validator_source = "\n".join(lines[validator_start - 1 : validator.end_lineno]) + "\n"
    if _sha256_bytes(validator_source.encode("utf-8")) != _REVIEWED_DARWIN_CONTAINMENT_SECTIONS[
        "_validate_macos_launch_parent"
    ] or any(
        isinstance(node, ast.Name)
        and node.id == "_validate_macos_launch_parent"
        and isinstance(node.ctx, (ast.Store, ast.Del))
        for node in ast.walk(tree)
    ):
        return False
    calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and _ast_qualified_name(node.func) == "popen_factory"
    ]
    if len(calls) != 2:
        return False
    parents = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}
    calls_by_function: dict[str, ast.Call] = {}
    functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
    for call in calls:
        function = _enclosing_function(call, parents)
        if function is None or function.name in calls_by_function:
            return False
        calls_by_function[function.name] = call
        functions[function.name] = function
    if set(calls_by_function) != {"spawn_no_fork_exec", "spawn_parent_death"}:
        return False

    common_keywords = (
        ("cwd", "work_root"),
        ("env", "dict(environment)"),
        ("stdin", "subprocess.DEVNULL"),
        ("stdout", "stdout"),
        ("stderr", "stderr"),
        ("shell", "False"),
        (None, "launch_options"),
    )
    parent_death = functions["spawn_parent_death"]
    parent_death_call = calls_by_function["spawn_parent_death"]
    parent_death_valid = (
        len(parent_death_call.args) == 1
        and _expression_matches(
            parent_death_call.args[0],
            """[
                interpreter_launch[0],
                "-I",
                "-B",
                "-X",
                "utf8",
                helper_launch[0],
                str(os.getpid()),
                str(child_socket.fileno()),
                str(target_descriptor),
                nonce,
                ",".join(str(value) for value in helper_descriptors),
                format(execution_timeout_seconds, ".17g"),
                *argv,
            ]""",
        )
        and _keyword_expressions_match(parent_death_call, common_keywords)
        and _function_parameter_is_unmodified(parent_death, "argv")
        and _function_parameter_is_unmodified(parent_death, "popen_factory")
        and _function_parameter_is_unmodified(parent_death, "execution_timeout_seconds")
        and _copied_options_mapping(
            parent_death,
            name="launch_options",
            source_name="options",
            assigned_keys={
                "pass_fds",
                "_bluefire_descriptor_argument_indexes",
                "_bluefire_descriptor_list_argument_indexes",
            },
        )
    )

    no_fork = functions["spawn_no_fork_exec"]
    no_fork_call = calls_by_function["spawn_no_fork_exec"]
    no_fork_valid = (
        len(no_fork_call.args) == 1
        and _expression_matches(
            no_fork_call.args[0],
            """[
                interpreter_launch[0],
                "-I",
                "-B",
                "-X",
                "utf8",
                helper_launch[0],
                _DARWIN_NO_FORK_EXEC_MODE,
                str(os.getpid()),
                str(child_socket.fileno()),
                str(target_descriptor),
                nonce,
                ",".join(str(value) for value in helper_descriptors),
                *argv,
            ]""",
        )
        and _keyword_expressions_match(no_fork_call, common_keywords)
        and _function_parameter_is_unmodified(no_fork, "argv")
        and _function_parameter_is_unmodified(no_fork, "popen_factory")
        and _copied_options_mapping(
            no_fork,
            name="launch_options",
            source_name="options",
            assigned_keys={
                "pass_fds",
                "_bluefire_descriptor_argument_indexes",
                "_bluefire_descriptor_list_argument_indexes",
            },
        )
    )
    return parent_death_valid and no_fork_valid


def _runner_parent_death_process_contract(path: Path, repository: Path) -> bool:
    """Lock Darwin/Linux helper execution to three forks and three execve calls."""

    text = path.read_text(encoding="utf-8")
    if _sha256_bytes(text.encode("utf-8")) != _REVIEWED_PARENT_DEATH_SOURCE_SHA256:
        return False
    tree = ast.parse(text, filename=path.name)
    findings = _python_shell_findings(path, repository)
    calls = [
        _ast_qualified_name(node.func) for node in ast.walk(tree) if isinstance(node, ast.Call)
    ]
    fork_aliases = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Name) and target.id == "_FORK_PROCESS" for target in node.targets
        )
    ]
    return (
        len(fork_aliases) == 1
        and _expression_matches(fork_aliases[0].value, 'getattr(os, "fork", None)')
        and calls.count("_FORK_PROCESS") == 3
        and calls.count("os.execve") == 3
        and [(item.get("kind"), item.get("call")) for item in findings]
        == [
            ("dynamic_execution_lookup", "os.fork"),
            ("dynamic_execution_call", "os.execve"),
            ("dynamic_execution_call", "os.execve"),
            ("dynamic_execution_call", "os.execve"),
        ]
        and 'ctypes.CDLL("/usr/lib/libsandbox.1.dylib", use_errno=True)' in text
        and 'ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)' in text
        and "subprocess" not in text
    )


def _python_shell_findings(path: Path, repository: Path) -> list[dict[str, Any]]:
    text = path.read_text(encoding="utf-8")
    tree = ast.parse(text, filename=path.name)
    findings: list[dict[str, Any]] = []
    module_aliases, symbol_aliases = _python_aliases(tree)

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name in PYTHON_SHELL_MODULES:
                    findings.append({"kind": "shell_import", "line": node.lineno})
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            imports_shell_symbol = any(alias.name in PYTHON_SHELL_CALLS for alias in node.names)
            if module in PYTHON_SHELL_MODULES or (
                module in {"asyncio", "os"} and imports_shell_symbol
            ):
                findings.append({"kind": "shell_import", "line": node.lineno})

    for node in ast.walk(tree):
        value = _assignment_value(node)
        if value is None or not isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
            continue
        resolved_value = _resolved_python_name(value, module_aliases, symbol_aliases)
        targets = _simple_assignment_targets(node)
        sensitive_rebinds = [
            target
            for target in targets
            if isinstance(target, ast.Name)
            and _sensitive_callable_reference(
                module_aliases.get(target.id, symbol_aliases.get(target.id, ""))
            )
        ]
        if sensitive_rebinds and not _sensitive_callable_reference(resolved_value):
            findings.append(
                {
                    "kind": "dynamic_execution_rebind",
                    "line": node.lineno,
                    "call": "dynamic",
                }
            )
        if not _sensitive_callable_reference(resolved_value):
            continue
        for target in targets:
            if isinstance(target, ast.Name):
                symbol_aliases[target.id] = resolved_value
        findings.append(
            {
                "kind": "dynamic_execution_alias",
                "line": node.lineno,
                "call": resolved_value,
            }
        )

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        resolved_name = _resolved_python_name(node.func, module_aliases, symbol_aliases)
        if _is_dynamic_execution_name(resolved_name):
            findings.append(
                {
                    "kind": "dynamic_execution_call",
                    "line": node.lineno,
                    "call": resolved_name,
                }
            )
        if resolved_name in PYTHON_DYNAMIC_NAMESPACE_CALLS:
            findings.append(
                {
                    "kind": "dynamic_namespace_access",
                    "line": node.lineno,
                    "call": resolved_name,
                }
            )
        if not isinstance(node.func, (ast.Name, ast.Attribute)):
            hidden_references = {
                _resolved_python_name(child, module_aliases, symbol_aliases)
                for child in ast.walk(node.func)
                if isinstance(child, (ast.Name, ast.Attribute))
            }
            hidden_sensitive = sorted(
                name
                for name in hidden_references
                if name in PYTHON_DYNAMIC_IMPORT_CALLS or _is_dynamic_execution_name(name)
            )
            if hidden_sensitive:
                findings.append(
                    {
                        "kind": "dynamic_execution_target",
                        "line": node.lineno,
                        "call": hidden_sensitive[0],
                    }
                )
        if resolved_name in PYTHON_DYNAMIC_IMPORT_CALLS:
            imported = node.args[0] if node.args else None
            module = (
                imported.value
                if isinstance(imported, ast.Constant) and isinstance(imported.value, str)
                else "dynamic"
            )
            findings.append(
                {
                    "kind": "dynamic_shell_import",
                    "line": node.lineno,
                    "module": module,
                }
            )
        if resolved_name in {"getattr", "builtins.getattr"} and len(node.args) >= 2:
            attribute = node.args[1]
            resolved_target = _resolved_python_name(node.args[0], module_aliases, symbol_aliases)
            attribute_name = (
                attribute.value
                if isinstance(attribute, ast.Constant) and isinstance(attribute.value, str)
                else None
            )
            dynamic_attribute = attribute_name is None
            dangerous_attribute = attribute_name is not None and (
                attribute_name in PYTHON_SHELL_CALLS
                or attribute_name.startswith("exec")
                or attribute_name.startswith("spawn")
            )
            if resolved_target in {"asyncio", "os", "subprocess"} and (
                dynamic_attribute or dangerous_attribute
            ):
                findings.append(
                    {
                        "kind": "dynamic_execution_lookup",
                        "line": node.lineno,
                        "call": (
                            f"{resolved_target}.{attribute_name}"
                            if not dynamic_attribute
                            else f"{resolved_target}.<dynamic>"
                        ),
                    }
                )
        if any(
            keyword.arg == "shell"
            and isinstance(keyword.value, ast.Constant)
            and keyword.value.value is True
            for keyword in node.keywords
        ):
            findings.append({"kind": "shell_true", "line": node.lineno})
    relative = path.relative_to(repository).as_posix()
    return [{"path": relative, **finding} for finding in findings]


_REVIEWED_PROCESS_SOURCE_SIZE = 25_856
_REVIEWED_PROCESS_SOURCE_SHA256 = (
    "sha256:4720059fa4289b994d7ba05df36e2de22efff9cc4c0b09fe07509dc972c4694b"
)
_REVIEWED_CANCELLATION_SOURCE_SIZE = 31_960
_REVIEWED_CANCELLATION_SOURCE_SHA256 = (
    "sha256:4b3aaebb36b496e8ba2af5fe64eeb3b9925af031a8e2ff42741ad80b8ba07854"
)


def _macos_process_inventory_is_in_process(process_text: str) -> bool:
    start = process_text.find('#[cfg(target_os = "macos")]\nmod macos_process_api')
    end = process_text.find('#[cfg(target_os = "windows")]\nmod windows_process_api', start)
    if start < 0 or end <= start:
        return False
    macos = process_text[start:end]
    return (
        "proc_listallpids" in macos
        and "proc_pidinfo" in macos
        and "MAX_PROCESS_COUNT" in macos
        and "limits.max_stdout_bytes" in macos
        and "max_entries" in macos
        and "Command::new(" not in macos
        and ".spawn(" not in macos
        and "/bin/ps" not in macos
        and "/usr/bin/ps" not in macos
    )


def _native_process_inventory_is_fixed(process_source: bytes) -> bool:
    """Bind the complete reviewed Rust process boundary before checking its shape."""

    if (
        type(process_source) is not bytes
        or len(process_source) != _REVIEWED_PROCESS_SOURCE_SIZE
        or _sha256_bytes(process_source) != _REVIEWED_PROCESS_SOURCE_SHA256
    ):
        return False
    try:
        process_text = process_source.decode("utf-8")
    except UnicodeError:
        return False
    return (
        process_text.count("Command::new(") == 3
        and process_text.count("Command::new(&spec.executable)") == 1
        and process_text.count('Command::new("/bin/sleep")') == 1
        and process_text.count("Command::new(std::env::current_exe().unwrap())") == 1
        and process_text.count(".spawn()") == 2
        and process_text.count(".status()") == 1
        and process_text.count("use std::process::{Command, Stdio};") == 1
        and process_text.count("struct FixedProcessSpec") == 1
        and process_text.count('first_reviewed_program(&["/usr/bin/ps", "/bin/ps"])') == 1
        and process_text.count('args: vec!["-eo", "pid=,ppid=,comm="]') == 1
        and process_text.count(".env_clear()") == 2
        and _macos_process_inventory_is_in_process(process_text)
        and all(
            token not in process_text.casefold()
            for token in ("cmd.exe", "powershell", "/bin/sh", "/bin/bash", "sh -c")
        )
    )


def _native_command_source_inventory_is_fixed(repository: Path) -> bool:
    source_root = repository / "runner" / "src"
    command_sources: dict[str, bytes] = {}
    for path in source_root.rglob("*.rs"):
        source = path.read_bytes()
        if re.search(rb"\bCommand\b", source) is not None:
            command_sources[path.relative_to(source_root).as_posix()] = source
    if set(command_sources) != {"process.rs", "cancellation_witness.rs"}:
        return False
    cancellation_source = command_sources["cancellation_witness.rs"]
    if (
        len(cancellation_source) != _REVIEWED_CANCELLATION_SOURCE_SIZE
        or _sha256_bytes(cancellation_source) != _REVIEWED_CANCELLATION_SOURCE_SHA256
    ):
        return False
    try:
        cancellation_text = cancellation_source.decode("utf-8")
    except UnicodeError:
        return False
    return (
        cancellation_text.count("Command::new(") == 1
        and cancellation_text.count("Command::new(&executable)") == 1
        and "#[cfg(windows)]\nstruct DescendantGuard" in cancellation_text
        and "#[cfg(windows)]\nimpl DescendantGuard" in cancellation_text
        and "the process-tree cancellation witness is available only on Windows"
        in cancellation_text
        and _native_process_inventory_is_fixed(command_sources["process.rs"])
    )


def _trusted_process_boundary_inventory_is_fixed() -> bool:
    reviewed_paths = (
        *_REVIEWED_PYTHON_PROCESS_BOUNDARY_SOURCES,
        *_REVIEWED_RUST_PROCESS_BOUNDARY_SOURCES,
    )
    return (
        len(TRUSTED_PROCESS_BOUNDARY_PATHS) == len(set(TRUSTED_PROCESS_BOUNDARY_PATHS))
        and TRUSTED_PROCESS_BOUNDARY_PATHS == reviewed_paths
    )


def _reviewed_python_process_boundary_sources(texts: Mapping[str, str]) -> bool:
    return {
        name: _sha256_bytes(text.encode("utf-8")) for name, text in texts.items()
    } == _REVIEWED_PYTHON_PROCESS_BOUNDARY_SOURCES


def _process_boundary_report(repository: Path) -> dict[str, Any]:
    paths = {
        relative.removeprefix("bluefire/"): repository / relative
        for relative in _REVIEWED_PYTHON_PROCESS_BOUNDARY_SOURCES
    }
    texts = {f"bluefire/{name}": path.read_text(encoding="utf-8") for name, path in paths.items()}
    expected_calls = {
        "runner_client.py": ["subprocess.Popen", "subprocess.Popen"],
        "runner_bootstrap.py": [],
        "runner_darwin_containment.py": [],
        "runner_lifecycle.py": ["subprocess.Popen"],
        "runner_trust.py": [],
    }
    expected_imports = {
        "runner_client.py": 1,
        "runner_bootstrap.py": 0,
        "runner_darwin_containment.py": 1,
        "runner_lifecycle.py": 1,
        "runner_trust.py": 0,
    }
    python_boundaries: dict[str, Any] = {}
    for name, calls in expected_calls.items():
        findings = _python_shell_findings(paths[name], repository)
        actual_calls = sorted(
            str(item["call"])
            for item in findings
            if item.get("kind") == "dynamic_execution_call" and "call" in item
        )
        import_count = sum(item.get("kind") == "shell_import" for item in findings)
        unexpected = [
            item
            for item in findings
            if item.get("kind") not in {"shell_import", "dynamic_execution_call"}
        ]
        python_boundaries[name] = {
            "passed": import_count == expected_imports[name]
            and actual_calls == sorted(calls)
            and not unexpected,
            "shell_imports": import_count,
            "process_calls": actual_calls,
            "unexpected_findings": unexpected,
        }

    parent_death_findings = _python_shell_findings(paths["runner_parent_death.py"], repository)
    python_boundaries["runner_parent_death.py"] = {
        "passed": _runner_parent_death_process_contract(
            paths["runner_parent_death.py"], repository
        ),
        "shell_imports": sum(item.get("kind") == "shell_import" for item in parent_death_findings),
        "process_calls": sorted(
            str(item["call"]) for item in parent_death_findings if "call" in item
        ),
        "unexpected_findings": [],
    }

    client_text = texts["bluefire/runner_client.py"]
    bootstrap_text = texts["bluefire/runner_bootstrap.py"]
    lifecycle_text = texts["bluefire/runner_lifecycle.py"]
    trust_text = texts["bluefire/runner_trust.py"]
    service_text = (repository / "bluefire" / "service.py").read_text(encoding="utf-8")
    host_text = (repository / "bluefire" / "runner_host.py").read_text(encoding="utf-8")
    process_source = (repository / "runner" / "src" / "process.rs").read_bytes()
    checks = {
        "python_process_call_inventory": _trusted_process_boundary_inventory_is_fixed()
        and _reviewed_python_process_boundary_sources(texts)
        and all(item["passed"] is True for item in python_boundaries.values()),
        "popen_shell_disabled": _runner_client_popen_contract(paths["runner_client.py"])
        and _runner_darwin_popen_contract(paths["runner_darwin_containment.py"])
        and _runner_lifecycle_popen_contract(paths["runner_lifecycle.py"]),
        "absolute_digest_bound_runner": all(
            token in client_text
            for token in (
                "if not binary.is_absolute() or not binary.is_file()",
                "self.runner_binary = binary.resolve(strict=True)",
                "self.runner_binary_digest = file_hash(self.runner_binary)",
                "reject_forbidden_execution_keys(manifest)",
                "reject_forbidden_execution_keys(profile)",
                '[str(self.runner_binary), "inventory", "--json"]',
                '"execute",',
                '"--manifest",',
                '"--profile",',
            )
        ),
        "bootstrap_fixed_system_tools": not _python_shell_findings(
            paths["runner_bootstrap.py"], repository
        )
        and "apply_owner_private_acl_path" in bootstrap_text
        and "from .windows_owner_acl import" in bootstrap_text,
        "trust_fixed_system_tools": not _python_shell_findings(paths["runner_trust.py"], repository)
        and "apply_owner_private_acl_path" in trust_text
        and "_owner_private_native_handle" in trust_text,
        "lifecycle_uses_fixed_installed_host": all(
            token in lifecycle_text
            for token in (
                "self.host_command_factory = host_command_factory or _default_command_factory",
                "command = _validated_host_command(self.host_command_factory(spec))",
                "process = subprocess.Popen(command, shell=False, **options)",
            )
        )
        and "ManagedRunnerLifecycle(managed_product_root())" in service_text
        and all(
            token in host_text
            for token in (
                "str(Path(sys.executable).resolve())",
                '"-I"',
                '"-m"',
                '"bluefire.runner_host"',
            )
        ),
        "watchdog_has_no_process_launcher": not _python_shell_findings(
            paths["runner_watchdog.py"], repository
        ),
        "native_process_inventory_is_fixed": _native_process_inventory_is_fixed(process_source)
        and _native_command_source_inventory_is_fixed(repository),
    }
    return {
        "passed": all(checks.values()),
        "checks": checks,
        "python_boundaries": python_boundaries,
        "boundary": (
            "typed-model-output-to-reviewed-actions-to-fixed-absolute-digest-bound-runner-"
            "with-shell-disabled"
        ),
    }


def _source_audit(
    repository: Path,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    if not _trusted_process_boundary_inventory_is_fixed():
        raise ProviderGateError("trusted process-boundary inventory is not fully reviewed")
    files: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    for relative in SOURCE_AUDIT_PATHS:
        path = (repository / relative).resolve(strict=True)
        if not path.is_relative_to(repository) or not path.is_file():
            raise ProviderGateError("source audit path is unavailable")
        text = path.read_text(encoding="utf-8")
        files.append({"path": relative, "sha256": _sha256_bytes(text.encode("utf-8"))})
        if relative in TRUSTED_PROCESS_BOUNDARY_PATHS:
            continue
        if path.suffix == ".py":
            findings.extend(_python_shell_findings(path, repository))
        else:
            for token in RUST_SHELL_TOKENS:
                if token.casefold() in text.casefold():
                    findings.append({"path": relative, "kind": "shell_token", "token": token})
    return files, findings, _process_boundary_report(repository)
