from __future__ import annotations

import sys
from pathlib import Path
from types import ModuleType
from typing import Any, Mapping

import pytest

import bluefire.cross_platform_source_intake_probe as probe_runtime

_PROBE_MODULE = "bluefire._gate11_source_intake_probe"
_PROBE_DIGEST = "sha256:" + "a" * 64


def test_bound_staged_probe_verifies_identity_before_import_and_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    product_root = tmp_path / "site"
    workspace = tmp_path / "workspace"
    events: list[tuple[str, Any]] = []
    probe = ModuleType(_PROBE_MODULE)

    def run_probes(observed_workspace: Path) -> Mapping[str, Any]:
        events.append(("execute", observed_workspace))
        return {"passed": True}

    probe.__dict__["run_probes"] = run_probes
    monkeypatch.delitem(sys.modules, _PROBE_MODULE, raising=False)

    def identity_reader(path: Path, maximum: int) -> tuple[int, str]:
        assert _PROBE_MODULE not in sys.modules
        events.append(("identity", (path, maximum)))
        return 227, _PROBE_DIGEST

    def import_module(name: str) -> ModuleType:
        assert name == _PROBE_MODULE
        assert _PROBE_MODULE not in sys.modules
        events.append(("import", name))
        return probe

    monkeypatch.setattr(probe_runtime.importlib, "import_module", import_module)
    result = probe_runtime.run_bound_staged_probe(
        product_root,
        workspace,
        {"size": 227, "sha256": _PROBE_DIGEST},
        identity_reader,
    )

    assert result == {"passed": True}
    assert events == [
        (
            "identity",
            (product_root / "bluefire" / "_gate11_source_intake_probe.py", 64 * 1024),
        ),
        ("import", _PROBE_MODULE),
        ("execute", workspace),
    ]


def test_bound_staged_probe_refuses_preloaded_module_before_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class BoundaryError(ValueError):
        pass

    probe = ModuleType(_PROBE_MODULE)
    monkeypatch.setitem(sys.modules, _PROBE_MODULE, probe)

    def identity_reader(_path: Path, _maximum: int) -> tuple[int, str]:
        pytest.fail("a preloaded probe must be rejected before identity verification")

    with pytest.raises(BoundaryError, match="module was already loaded"):
        probe_runtime.run_bound_staged_probe(
            tmp_path / "site",
            tmp_path / "workspace",
            {"size": 227, "sha256": _PROBE_DIGEST},
            identity_reader,
            BoundaryError,
        )

    assert sys.modules[_PROBE_MODULE] is probe


def test_bound_staged_probe_refuses_module_loaded_during_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class BoundaryError(ValueError):
        pass

    probe = ModuleType(_PROBE_MODULE)
    observed: list[tuple[Path, int]] = []
    monkeypatch.delitem(sys.modules, _PROBE_MODULE, raising=False)

    def identity_reader(path: Path, maximum: int) -> tuple[int, str]:
        observed.append((path, maximum))
        monkeypatch.setitem(sys.modules, _PROBE_MODULE, probe)
        return 227, _PROBE_DIGEST

    with pytest.raises(BoundaryError, match="loaded during identity verification"):
        probe_runtime.run_bound_staged_probe(
            tmp_path / "site",
            tmp_path / "workspace",
            {"size": 227, "sha256": _PROBE_DIGEST},
            identity_reader,
            BoundaryError,
        )

    assert observed == [
        (tmp_path / "site" / "bluefire" / "_gate11_source_intake_probe.py", 64 * 1024)
    ]
    assert sys.modules[_PROBE_MODULE] is probe


def test_bound_staged_probe_refuses_identity_mismatch_before_import(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class BoundaryError(ValueError):
        pass

    product_root = tmp_path / "site"
    observed: list[tuple[Path, int]] = []
    monkeypatch.delitem(sys.modules, _PROBE_MODULE, raising=False)

    def identity_reader(path: Path, maximum: int) -> tuple[int, str]:
        observed.append((path, maximum))
        return 226, _PROBE_DIGEST

    with pytest.raises(BoundaryError, match="probe identity changed"):
        probe_runtime.run_bound_staged_probe(
            product_root,
            tmp_path / "workspace",
            {"size": 227, "sha256": _PROBE_DIGEST},
            identity_reader,
            BoundaryError,
        )

    assert observed == [(product_root / "bluefire" / "_gate11_source_intake_probe.py", 64 * 1024)]
    assert _PROBE_MODULE not in sys.modules
