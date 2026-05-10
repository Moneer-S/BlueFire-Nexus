# Preserved orphan files — decision report

This report documents three small files that live outside the
runtime module registry but are intentionally kept in tree. Each
exists for a real reason; this page makes that reason explicit so
future readers do not mistake them for dead code.

**No file in this report is a deletion candidate.** Each is
preserved as a compatibility shim, defensive helper, or gated
research capability per the project's standing principle of
gating dangerous behaviour rather than removing it. Smoke tests
in `tests/test_orphan_files_smoke.py` pin that each file stays
importable, so accidental breakage during refactors is caught at
test time.

| File | Classification | Why preserved |
|---|---|---|
| `src/core/bluefire.py` | Compatibility shim | Re-exports `cli.main` for legacy `python -m src.core.bluefire` invocations. |
| `src/legal_safeguards.py` | Defensive helper | `secure_wipe(path)` for lab-cleanup workflows. |
| `src/modules/evasion_techniques.py` | Gated research capability | Windows memory-evasion research class. Not in the runtime registry. |

## `src/core/bluefire.py`

```python
"""Compatibility entrypoint for legacy bluefire command paths."""

from .cli import main

if __name__ == "__main__":
    main()
```

A two-line module re-exporting `cli.main` so historic invocations
of the form `python -m src.core.bluefire` keep working. The
canonical CLI entry point is `python -m src.core.cli`; this shim
exists so external scripts and operator habits that pre-date the
canonical name continue to work without code changes.

**Decision: keep as compatibility shim.** No callers outside the
project should depend on this path, but removing it would silently
break any existing script that does. Cost of preservation: 8 lines
and one smoke test.

## `src/legal_safeguards.py`

```python
def secure_wipe(path):
    """
    Overwrites the file with random data, then deletes it.
    Effectiveness depends on filesystem and hardware specifics.
    """
    ...
```

A small defensive helper for lab-cleanup workflows: overwrite a
file with `os.urandom`, fsync, then unlink. Used by operators who
want to scrub artifacts after a purple-team run on a shared
filesystem. Effectiveness depends on filesystem and hardware
specifics (the docstring is honest about that — modern SSDs with
TRIM and copy-on-write filesystems make secure-wipe semantics
unreliable at the application layer).

**Decision: preserve as defensive helper.** The function is well
scoped, has no dangerous side effects beyond what its docstring
describes, and serves a real workflow. Removing it would silently
break the (small) set of lab automation scripts that import it.
Cost of preservation: 18 lines and one smoke test.

## `src/modules/evasion_techniques.py`

```python
class AdvancedEvasion:
    """
    Provides advanced memory and execution evasion techniques on Windows
    systems. Uses dynamic memory protection toggling to minimize exposure
    of RWX pages.
    """
    ...
```

Windows-only memory-evasion research code. Implements a
Foliage-style ROP-chain memory-encryption pattern: allocate
read-write memory via `VirtualAlloc`, copy a shellcode payload in,
flip the page to `PAGE_EXECUTE_READ` via `VirtualProtect`, run
the payload in a new thread via `CreateThread`, then free the
memory after `WaitForSingleObject` returns.

This is preserved adversary-research capability — exactly the
kind of code the project's standing principle says to **gate**
rather than delete. The class:

- Is **NOT registered** in the runtime module registry. The
  scenario runner cannot reach it through the standard
  `module: ...` step interface; it is reachable only via direct
  Python import.
- Is **Windows-only** by design. The `ctypes.WinDLL('kernel32')`
  and `ctypes.WinDLL('ntdll')` calls fail on non-Windows hosts at
  class-instantiation time, so the file stays import-safe on
  Linux / macOS CI even though instantiation is a noop there.
- Carries an explicit `# nosec B413` annotation justifying the
  `Crypto` import (resolves to pycryptodome — the actively
  maintained drop-in replacement for the deprecated pycrypto;
  pinned in `pyproject.toml`).

**Decision: preserve as gated research capability.** The standard
`defense_evasion` module already provides simulate-only telemetry
shaping for the same MITRE techniques (T1027 / T1036 / T1497 /
T1562 / T1070); this preserved class is the dual-use reference
implementation that lab operators can consult or wrap behind a
custom legacy adapter when they need real Windows tradecraft for
authorised research. The smoke test in
`tests/test_orphan_files_smoke.py` only checks that the file
remains a valid Python module — it does NOT instantiate
`AdvancedEvasion` because doing so would require Windows DLLs.
Cost of preservation: 101 lines and one import-only smoke test.

## Standing rule

If any of these three files needs to be moved, archived, or
deleted in the future, the change should:

1. Preserve the underlying capability (move, don't delete).
2. Update this report.
3. Update or remove the corresponding smoke test in
   `tests/test_orphan_files_smoke.py`.
4. Land in its own focused PR so the decision is reviewable.
