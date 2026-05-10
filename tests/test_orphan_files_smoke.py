"""Smoke tests for the three preserved files outside the registry.

The files covered by this test suite:

- ``src/core/bluefire.py`` — compatibility shim re-exporting
  ``cli.main`` for legacy ``python -m src.core.bluefire``
  invocations.
- ``src/legal_safeguards.py`` — defensive ``secure_wipe`` helper
  for lab-cleanup workflows.
- ``src/modules/evasion_techniques.py`` — Windows-only memory-
  evasion research class (NOT in the runtime module registry).

These tests pin the files' importability and minimum behaviour so
an accidental breakage during refactors surfaces here rather than
at runtime against operator scripts.

The Windows-specific evasion research file is import-tested only
(no instantiation) because ``ctypes.WinDLL('kernel32')`` requires
Windows. The smoke tests are platform-portable.
"""

from __future__ import annotations

import importlib
import os
from pathlib import Path

import pytest


# ---------------------------------------------------------------------------
# 1. src/core/bluefire.py — CLI compatibility shim
# ---------------------------------------------------------------------------


def test_core_bluefire_shim_imports_cli_main() -> None:
    """The shim exposes the canonical CLI entry as ``main``.

    The shim's whole purpose is so legacy invocations like
    ``python -m src.core.bluefire`` continue to dispatch to the
    same entry as ``python -m src.core.cli``. Failing this means
    the shim is effectively broken.
    """
    module = importlib.import_module("src.core.bluefire")
    assert hasattr(module, "main")
    assert callable(module.main)
    # The same `main` should be the canonical CLI's `main`.
    cli = importlib.import_module("src.core.cli")
    assert module.main is cli.main


# ---------------------------------------------------------------------------
# 2. src/legal_safeguards.py — secure_wipe helper
# ---------------------------------------------------------------------------


def test_legal_safeguards_secure_wipe_imports_and_is_callable() -> None:
    module = importlib.import_module("src.legal_safeguards")
    assert hasattr(module, "secure_wipe")
    assert callable(module.secure_wipe)


def test_legal_safeguards_secure_wipe_handles_missing_path(tmp_path: Path) -> None:
    """Missing input path is a noop, not an exception.

    Pin the documented behaviour of the helper: if the file is
    already gone, the call returns silently rather than raising
    ``FileNotFoundError``. Lab cleanup scripts call this on a list
    of paths and rely on the noop semantics for paths that may or
    may not exist.
    """
    from src.legal_safeguards import secure_wipe

    missing = tmp_path / "definitely-not-a-file"
    # No exception, no return value to inspect.
    secure_wipe(str(missing))


def test_legal_safeguards_secure_wipe_removes_existing_file(tmp_path: Path) -> None:
    """End-to-end: wipe an actual file in the tmp dir and verify removal.

    Defends the "overwrite-then-delete" contract. We do not assert
    on the on-disk byte content (the file is gone after the call,
    by design); we assert the file no longer exists.
    """
    from src.legal_safeguards import secure_wipe

    target = tmp_path / "scratch.bin"
    target.write_bytes(b"some-sensitive-content")
    assert target.exists()

    secure_wipe(str(target))
    assert not target.exists()


# ---------------------------------------------------------------------------
# 3. src/modules/evasion_techniques.py — Windows research module
# ---------------------------------------------------------------------------


def test_evasion_techniques_module_is_importable() -> None:
    """The module imports cleanly on every platform.

    On non-Windows hosts the import succeeds but instantiating
    ``AdvancedEvasion`` would fail at the
    ``ctypes.WinDLL('kernel32')`` call. We only verify import-
    safety here — instantiation is intentionally not exercised.

    A future regression that breaks the module's import (e.g.
    accidentally moving a Windows-only call to module top level)
    is caught here on Linux / macOS CI before it ships.
    """
    module = importlib.import_module("src.modules.evasion_techniques")
    assert hasattr(module, "AdvancedEvasion")
    # Class object is reachable (not instantiated).
    cls = module.AdvancedEvasion
    assert isinstance(cls, type)
    # The class documents the page-protection constants it uses.
    for attr in (
        "PAGE_READWRITE",
        "PAGE_EXECUTE_READ",
        "PAGE_EXECUTE_READWRITE",
        "MEM_COMMIT",
        "MEM_RESERVE",
    ):
        assert hasattr(cls, attr), attr


def test_evasion_techniques_module_is_not_in_runtime_registry() -> None:
    """The research class is NOT registered as a runtime module.

    Defends the "gated research, not standard module" status:
    operators MUST NOT be able to reach this class through the
    scenario runner's ``module: <name>`` step interface. Direct
    Python import is the only entry point.
    """
    from src.core.modules.registry import build_runtime_modules

    modules = build_runtime_modules()
    # Any registered module that exposes the research class would
    # break the gating invariant.
    for name, instance in modules.items():
        cls = type(instance)
        assert cls.__module__ != "src.modules.evasion_techniques", (
            f"runtime module {name!r} is an instance of "
            f"AdvancedEvasion or a subclass — research class must "
            "stay outside the registry"
        )


