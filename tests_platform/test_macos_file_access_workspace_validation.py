"""Source-only drift checks; neither validator nor native bootstrap is imported."""

import ast
import builtins
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1] / "bluefire"
_BOOTSTRAP = "macos_file_access_workspace_bootstrap"
_VALIDATION = "macos_file_access_workspace_validation"
_DEFINITIONS = (
    "_refuse",
    "_os_flag",
    "_FsId",
    "_StatFs",
    "_descriptor_security",
    "_directory",
    "_parents",
    "_import_inventory",
    "_protected_file",
)
_IMPORTS = """from __future__ import annotations
import ctypes
import errno
import hashlib
import os
import stat
import sys
from pathlib import Path
from typing import NoReturn, cast
"""


def _module(name: str) -> ast.Module:
    path = _ROOT / f"{name}.py"
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _definitions(module: ast.Module) -> dict[str, ast.FunctionDef | ast.ClassDef]:
    return {
        node.name: node for node in module.body if isinstance(node, (ast.FunctionDef, ast.ClassDef))
    }


@pytest.mark.parametrize("name", _DEFINITIONS)
def test_host_pretrust_predicate_is_ast_identical_to_standalone_bootstrap(name):
    original = _definitions(_module(_BOOTSTRAP))[name]
    copied = _definitions(_module(_VALIDATION))[name]
    assert ast.dump(copied, include_attributes=False) == ast.dump(
        original, include_attributes=False
    )


def test_host_pretrust_predicate_dependency_closure_is_standalone_and_exact():
    module = _module(_VALIDATION)
    definitions = _definitions(module)
    assert set(definitions) == set(_DEFINITIONS)
    assert len(module.body) == 1 + len(ast.parse(_IMPORTS).body) + len(_DEFINITIONS)
    assert isinstance(module.body[0], ast.Expr)
    assert isinstance(module.body[0].value, ast.Constant)
    assert isinstance(module.body[0].value.value, str)
    imports = [node for node in module.body if isinstance(node, (ast.Import, ast.ImportFrom))]
    assert [ast.dump(node) for node in imports] == [
        ast.dump(node) for node in ast.parse(_IMPORTS).body
    ]
    imported = {"ctypes", "errno", "hashlib", "os", "stat", "sys", "Path", "NoReturn", "cast"}
    available = imported | set(definitions) | set(dir(builtins))
    for definition in definitions.values():
        nodes = tuple(ast.walk(definition))
        bound = {
            node.id
            for node in nodes
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store)
        }
        bound.update(node.arg for node in nodes if isinstance(node, ast.arg))
        bound.update(
            node.name for node in nodes if isinstance(node, (ast.FunctionDef, ast.ClassDef))
        )
        loaded = {
            node.id
            for node in nodes
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load)
        }
        assert not any(isinstance(node, (ast.Global, ast.Nonlocal)) for node in nodes)
        assert loaded - bound <= available


def test_host_validator_boundary_does_not_import_the_pretrust_adapter():
    workspace = _module("macos_file_access_workspace")
    imports = [node for node in ast.walk(workspace) if isinstance(node, ast.ImportFrom)]
    assert any(
        node.level == 1
        and node.module is None
        and any(alias.name == _VALIDATION and alias.asname == "validation" for alias in node.names)
        for node in imports
    )
    assert all(
        node.module != _BOOTSTRAP and all(alias.name != _BOOTSTRAP for alias in node.names)
        for node in imports
    )
    bridge = _module("macos_file_access_bridge")
    assert all(
        node.module != _BOOTSTRAP for node in ast.walk(bridge) if isinstance(node, ast.ImportFrom)
    )
    endpoint = _definitions(bridge)["MacOSWorkspaceTaskEndpoint"]
    assert isinstance(endpoint, ast.ClassDef)
    assert [base.id for base in endpoint.bases if isinstance(base, ast.Name)] == ["Protocol"]
    assert {node.name for node in endpoint.body if isinstance(node, ast.FunctionDef)} == {
        "assert_current",
        "review_context",
        "dispatch_committed",
    }
    assert all(
        node.module != _VALIDATION and all(alias.name != _VALIDATION for alias in node.names)
        for node in ast.walk(_module(_BOOTSTRAP))
        if isinstance(node, ast.ImportFrom)
    )


def test_endpoint_socket_constant_keeps_the_bootstrap_integer_compatibility_check():
    original = _definitions(_module(_BOOTSTRAP))["_socket_constant"]
    copied = _definitions(_module("macos_file_access_endpoint"))["_socket_constant"]
    assert ast.dump(copied, include_attributes=False) == ast.dump(
        original, include_attributes=False
    )


def test_endpoint_import_stays_after_both_verified_inventories_and_canonical_alias():
    handshake = _definitions(_module(_BOOTSTRAP))["_handshake"]
    assert isinstance(handshake, ast.FunctionDef)
    inventories = [
        node
        for node in ast.walk(handshake)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "_import_inventory"
    ]
    assert len(inventories) == 2
    imports = [
        node
        for node in handshake.body
        if isinstance(node, ast.ImportFrom) and node.module and node.module.startswith("bluefire")
    ]
    endpoint_imports = [
        node for node in imports if node.module == "bluefire.macos_file_access_endpoint"
    ]
    assert len(endpoint_imports) == 1
    assert endpoint_imports[0].names[0].name == "OriginalWorkspaceEndpoint"
    first_import = min(node.lineno for node in imports)
    assert all(node.end_lineno < first_import for node in inventories)
    inserted_path = [
        node
        for node in ast.walk(handshake)
        if isinstance(node, ast.Call) and ast.unparse(node.func) == "sys.path.insert"
    ]
    canonical_alias = [
        node
        for node in ast.walk(handshake)
        if isinstance(node, ast.Assign)
        and any(ast.unparse(target) == "sys.modules[canonical_name]" for target in node.targets)
    ]
    assert len(inserted_path) == len(canonical_alias) == 1
    assert max(node.end_lineno for node in inventories) < inserted_path[0].lineno
    assert inserted_path[0].end_lineno < canonical_alias[0].lineno < first_import
    assert "bluefire.macos_file_access_workspace_bootstrap" in ast.unparse(handshake)


def test_endpoint_parent_guard_is_fixed_by_handshake_before_first_use():
    handshake = _definitions(_module(_BOOTSTRAP))["_handshake"]
    bindings = [
        node
        for node in ast.walk(handshake)
        if isinstance(node, ast.Assign)
        and any(ast.unparse(target) == "value._parent_guard" for target in node.targets)
    ]
    assert len(bindings) == 1
    assert isinstance(bindings[0].value, ast.Name)
    assert bindings[0].value.id == "_parent_current"
    endpoint_uses = [
        node
        for node in ast.walk(handshake)
        if isinstance(node, ast.Attribute)
        and isinstance(node.ctx, ast.Load)
        and isinstance(node.value, ast.Name)
        and node.value.id == "value"
    ]
    assert all(bindings[0].end_lineno < node.lineno for node in endpoint_uses)
    endpoint = _module("macos_file_access_endpoint")
    assert all(
        node.module != _BOOTSTRAP for node in ast.walk(endpoint) if isinstance(node, ast.ImportFrom)
    )
    definition = _definitions(endpoint)["OriginalWorkspaceEndpoint"]
    calls = [
        node
        for node in ast.walk(definition)
        if isinstance(node, ast.Call) and ast.unparse(node.func) == "self._parent_guard"
    ]
    assert len(calls) == 1
    assert [ast.unparse(argument) for argument in calls[0].args] == [
        "self._recipe",
        "self._stream",
    ]
