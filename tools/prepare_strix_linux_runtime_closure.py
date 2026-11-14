"""Assemble the exact private Linux runtime used by the controlled Strix worker.

The CLI is deliberately offline.  It consumes the qualified Strix venv and
wheelhouse, the exact candidate wheel, a dedicated minimal BlueFire worker
artifact, and the CPython files supplied by the pinned setup-python action.
It emits a new immutable closure plus path-redacted preparation evidence.

Preparation is not startup qualification.  The native fixed-exec launcher
must subsequently start this exact tree inside its private root and issue the
separate post-launch receipt.
"""

from __future__ import annotations

from tools.strix_runtime_closure_common import (
    StrixRuntimeClosurePreparationError,
    _canonical_json,
    _copy_payload,
    _digest_bytes,
    _document_bytes,
)
from tools.strix_runtime_closure_elf import ElfIdentity, _elf_identity
from tools.strix_runtime_closure_prepare_core import (
    BOOTSTRAP_DESTINATION,
    CPYTHON_SOURCE_SCHEMA,
    ELF_NAME,
    ELF_SCHEMA,
    INVENTORY_SCHEMA,
    LOADER_DESTINATION,
    LOCKDOWN_DESTINATION,
    PREPARATION_NAME,
    PREPARATION_SCHEMA,
    PRIVATE_DIRECTORIES,
    PRIVATE_MOUNTPOINTS,
    ROOT_NAME,
    SBOM_SCHEMA,
    main,
    prepare_strix_linux_runtime_closure,
)
from tools.strix_runtime_closure_wheel import (
    WheelEntry,
    WheelPlan,
    _plan_wheel,
)

__all__ = [
    "BOOTSTRAP_DESTINATION",
    "CPYTHON_SOURCE_SCHEMA",
    "ELF_NAME",
    "ELF_SCHEMA",
    "ElfIdentity",
    "INVENTORY_SCHEMA",
    "LOADER_DESTINATION",
    "LOCKDOWN_DESTINATION",
    "PREPARATION_NAME",
    "PREPARATION_SCHEMA",
    "PRIVATE_DIRECTORIES",
    "PRIVATE_MOUNTPOINTS",
    "ROOT_NAME",
    "SBOM_SCHEMA",
    "StrixRuntimeClosurePreparationError",
    "WheelEntry",
    "WheelPlan",
    "_canonical_json",
    "_copy_payload",
    "_digest_bytes",
    "_document_bytes",
    "_elf_identity",
    "_plan_wheel",
    "main",
    "prepare_strix_linux_runtime_closure",
]


if __name__ == "__main__":
    raise SystemExit(main())
