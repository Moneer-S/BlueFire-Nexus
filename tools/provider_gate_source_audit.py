"""Static process-boundary and source auditing for provider acceptance."""

from __future__ import annotations

import ast
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
    forwarded_to: tuple[str, str] | None = None,
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
            if (
                forwarded_to is not None
                and isinstance(parent, ast.keyword)
                and parent.arg == forwarded_to[1]
            ):
                owner = parents.get(parent)
                if (
                    isinstance(owner, ast.Call)
                    and _ast_qualified_name(owner.func) == forwarded_to[0]
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
    expected_forwards = 1 if forwarded_to is not None else 0
    return (
        expansions == 1
        and forwards == expected_forwards
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
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=path.name)
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
    if (
        len(parent_death_calls) != 1
        or _enclosing_function(parent_death_calls[0], parents) is not spawn
    ):
        return False
    parent_death_forward = parent_death_calls[0]
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
        and _fixed_options_mapping(
            spawn,
            name="options",
            initial_keys=set(),
            assigned_keys={"creationflags", "start_new_session", "pass_fds"},
            forwarded_to=("self._spawn_linux_parent_death", "options"),
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
    return spawn_valid and parent_death_valid


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


def _process_boundary_report(repository: Path) -> dict[str, Any]:
    paths = {
        name: repository / "bluefire" / name
        for name in (
            "runner_client.py",
            "runner_bootstrap.py",
            "runner_lifecycle.py",
            "runner_trust.py",
            "runner_watchdog.py",
        )
    }
    texts = {name: path.read_text(encoding="utf-8") for name, path in paths.items()}
    expected_calls = {
        "runner_client.py": ["subprocess.Popen", "subprocess.Popen"],
        "runner_bootstrap.py": ["subprocess.run", "subprocess.run"],
        "runner_lifecycle.py": ["subprocess.Popen"],
        "runner_trust.py": ["subprocess.run", "subprocess.run"],
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
            "passed": import_count == 1 and actual_calls == sorted(calls) and not unexpected,
            "shell_imports": import_count,
            "process_calls": actual_calls,
            "unexpected_findings": unexpected,
        }

    client_text = texts["runner_client.py"]
    bootstrap_text = texts["runner_bootstrap.py"]
    lifecycle_text = texts["runner_lifecycle.py"]
    trust_text = texts["runner_trust.py"]
    service_text = (repository / "bluefire" / "service.py").read_text(encoding="utf-8")
    host_text = (repository / "bluefire" / "runner_host.py").read_text(encoding="utf-8")
    process_text = (repository / "runner" / "src" / "process.rs").read_text(encoding="utf-8")
    checks = {
        "python_process_call_inventory": all(
            item["passed"] is True for item in python_boundaries.values()
        ),
        "popen_shell_disabled": _runner_client_popen_contract(paths["runner_client.py"])
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
        "bootstrap_fixed_system_tools": "shell" not in bootstrap_text
        and "whoami.exe" in bootstrap_text
        and "icacls.exe" in bootstrap_text
        and 'system_root / "System32"' in bootstrap_text,
        "trust_fixed_system_tools": "shell" not in trust_text
        and "whoami.exe" in trust_text
        and "icacls.exe" in trust_text
        and "_windows_system_directory()" in trust_text,
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
        "native_process_inventory_is_fixed": process_text.count("Command::new(") == 1
        and "struct FixedProcessSpec" in process_text
        and 'first_reviewed_program(&["/usr/bin/ps", "/bin/ps"])' in process_text
        and 'first_reviewed_program(&["/bin/ps", "/usr/bin/ps"])' in process_text
        and 'args: vec!["-eo", "pid=,ppid=,comm="]' in process_text
        and 'args: vec!["-axo", "pid=,ppid=,comm="]' in process_text
        and ".env_clear()" in process_text
        and all(
            token not in process_text.casefold()
            for token in ("cmd.exe", "powershell", "/bin/sh", "/bin/bash", "sh -c")
        ),
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
