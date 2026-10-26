"""Fixed, bounded code-site diagnostics for protected macOS setup failures."""

from __future__ import annotations

from typing import Any

_PACKAGE_IMPORT_SITE_OFFSETS = {
    "package_root_ancestry": frozenset({1}),
    "package_root_inventory_call": frozenset({2}),
    "package_ancestor_path": frozenset({1}),
    "package_ancestor_directory": frozenset({3}),
    "package_walk_root": frozenset({3}),
    "package_walk_directory": frozenset({10}) | frozenset(range(12, 20)),
    "package_walk_file_inventory": frozenset(range(20, 29)),
    "package_walk_complete": frozenset({29}),
    "package_directory_open": frozenset(range(1, 4)),
    "package_directory_custody": frozenset(range(4, 12)),
    "package_directory_descriptor": frozenset({12}),
    "package_directory_release": frozenset({14}),
    "package_filesystem_abi": frozenset(range(2, 5)),
    "package_filesystem_policy": frozenset(range(5, 11)),
    "package_acl_lookup": frozenset(range(11, 26)),
    "package_acl_policy": frozenset(range(26, 34)),
    "package_file_open": frozenset(range(1, 3)),
    "package_file_custody": frozenset(range(3, 12)),
    "package_file_descriptor": frozenset({12}),
    "package_file_read": frozenset(range(13, 23)),
    "package_file_integrity": frozenset(range(23, 46)),
    "package_file_release": frozenset({46}),
    "package_hash_open": frozenset(range(3, 5)),
    "package_hash_custody": frozenset(range(5, 14)),
    "package_hash_descriptor": frozenset({14}),
    "package_hash_read": frozenset(range(15, 25)),
    "package_hash_integrity": frozenset(range(25, 32)),
    "package_hash_release": frozenset({32}),
    "package_inventory_bounds": frozenset(range(2, 9)) | frozenset({34, 35, 49}),
    "package_inventory_root": frozenset(range(16, 32)),
    "package_inventory_directory": frozenset({32, 36, 37, 38}),
    "package_inventory_walk": frozenset({33}),
    "package_inventory_file_references": frozenset(range(39, 49)),
    "package_inventory_complete": frozenset({50}),
}
_NAMESPACE_CREATION_SITE_OFFSETS = {
    "namespace_creator": frozenset(range(78)),
    "namespace_create": frozenset(range(44)),
    "namespace_root_prerequisite": frozenset(range(17)),
    "namespace_credentials": frozenset(range(14)),
    "namespace_directory_open": frozenset(range(14)),
    "namespace_descriptor_policy": frozenset(range(13)),
    "namespace_filesystem_policy": frozenset(range(10)),
    "namespace_descriptor_security": frozenset(range(64)),
    "namespace_sealed_resource": frozenset(range(60)),
    "namespace_binding": frozenset(range(26)),
    "namespace_worker_start": frozenset(range(122)),
    "namespace_worker_guard_wall_window": frozenset({8}),
    "namespace_worker_guard_deadline": frozenset({10}),
    "namespace_worker_guard_wall_clock_order": frozenset({12}),
    "namespace_worker_guard_monotonic_order": frozenset({14}),
}
SITE_OFFSETS = {
    "package_import_custody": _PACKAGE_IMPORT_SITE_OFFSETS,
    "namespace_creation": _NAMESPACE_CREATION_SITE_OFFSETS,
}
MAX_PACKAGE_OFFSET = 64
MAX_NAMESPACE_OFFSET = 128
MAX_OFFSETS = {
    "package_import_custody": MAX_PACKAGE_OFFSET,
    "namespace_creation": MAX_NAMESPACE_OFFSET,
}


def package_import_site_ranges(
    inventory_code: Any, validation: Any, walk_imports: Any, hash_file: Any
) -> tuple[Any, ...]:
    return (
        (inventory_code, ((1, 1, "package_root_ancestry"), (2, 2, "package_root_inventory_call"))),
        (
            walk_imports.__code__,
            (
                (3, 3, "package_walk_root"),
                (10, 10, "package_walk_directory"),
                (12, 19, "package_walk_directory"),
                (20, 28, "package_walk_file_inventory"),
                (29, 29, "package_walk_complete"),
            ),
        ),
        (
            hash_file.__code__,
            (
                (3, 4, "package_hash_open"),
                (5, 13, "package_hash_custody"),
                (14, 14, "package_hash_descriptor"),
                (15, 24, "package_hash_read"),
                (25, 31, "package_hash_integrity"),
                (32, 32, "package_hash_release"),
            ),
        ),
        (
            validation._parents.__code__,
            ((1, 1, "package_ancestor_path"), (3, 3, "package_ancestor_directory")),
        ),
        (
            validation._directory.__code__,
            (
                (1, 3, "package_directory_open"),
                (4, 11, "package_directory_custody"),
                (12, 12, "package_directory_descriptor"),
                (14, 14, "package_directory_release"),
            ),
        ),
        (
            validation._descriptor_security.__code__,
            (
                (2, 4, "package_filesystem_abi"),
                (5, 10, "package_filesystem_policy"),
                (11, 25, "package_acl_lookup"),
                (26, 33, "package_acl_policy"),
            ),
        ),
        (
            validation._import_inventory.__code__,
            (
                (2, 8, "package_inventory_bounds"),
                (16, 31, "package_inventory_root"),
                (32, 32, "package_inventory_directory"),
                (33, 33, "package_inventory_walk"),
                (34, 35, "package_inventory_bounds"),
                (36, 38, "package_inventory_directory"),
                (39, 48, "package_inventory_file_references"),
                (49, 49, "package_inventory_bounds"),
                (50, 50, "package_inventory_complete"),
            ),
        ),
        (
            validation._protected_file.__code__,
            (
                (1, 2, "package_file_open"),
                (3, 11, "package_file_custody"),
                (12, 12, "package_file_descriptor"),
                (13, 22, "package_file_read"),
                (23, 45, "package_file_integrity"),
                (46, 46, "package_file_release"),
            ),
        ),
    )


def namespace_creation_site_ranges(
    creator: Any, namespace: Any, contract: Any, worker: Any
) -> tuple[Any, ...]:
    return (
        (creator.MacOSFileAccessCreator.create.__func__.__code__, ((0, 77, "namespace_creator"),)),
        (namespace.SealedMacOSNamespace.create.__func__.__code__, ((0, 43, "namespace_create"),)),
        (namespace._root.__code__, ((0, 16, "namespace_root_prerequisite"),)),
        (contract.validate_credentials.__code__, ((0, 13, "namespace_credentials"),)),
        (
            namespace.SealedMacOSNamespace._open_directory.__code__,
            ((0, 13, "namespace_directory_open"),),
        ),
        (namespace._directory.__code__, ((0, 12, "namespace_descriptor_policy"),)),
        (namespace._security.__code__, ((0, 9, "namespace_filesystem_policy"),)),
        (
            namespace._validate_darwin_descriptor_security.__code__,
            ((0, 63, "namespace_descriptor_security"),),
        ),
        (
            namespace.SealedMacOSNamespace._create.__code__,
            ((0, 59, "namespace_sealed_resource"),),
        ),
        (namespace.SealedMacOSNamespace.binding.__code__, ((0, 25, "namespace_binding"),)),
        (
            worker.MacOSFileAccessWorker.start.__code__,
            ((0, 121, "namespace_worker_start"),),
        ),
        (
            worker.MacOSFileAccessWorker._guard.__code__,
            (
                (8, 8, "namespace_worker_guard_wall_window"),
                (10, 10, "namespace_worker_guard_deadline"),
                (12, 12, "namespace_worker_guard_wall_clock_order"),
                (14, 14, "namespace_worker_guard_monotonic_order"),
            ),
        ),
    )


def site_for_frame(
    code: Any,
    offset: int,
    code_ranges: tuple[Any, ...],
    *,
    max_offset: int,
) -> tuple[bool, tuple[str, int] | None]:
    for candidate, ranges in code_ranges:
        if code is not candidate:
            continue
        if type(offset) is not int or not 0 <= offset <= max_offset:
            return True, None
        for first, last, label in ranges:
            if first <= offset <= last:
                return True, (label, offset)
        return True, None
    return False, None


def deepest_setup_site(
    exc: BaseException, code_ranges: tuple[Any, ...], *, max_offset: int
) -> tuple[str, int] | None:
    diagnostic = None
    traceback = exc.__traceback__
    while traceback is not None:
        code = traceback.tb_frame.f_code
        _, candidate = site_for_frame(
            code,
            traceback.tb_lineno - code.co_firstlineno,
            code_ranges,
            max_offset=max_offset,
        )
        if candidate is not None:
            diagnostic = candidate
        traceback = traceback.tb_next
    return diagnostic


def package_import_failure_site(
    exc: BaseException, inventory_code: Any, validation: Any, walk_imports: Any, hash_file: Any
) -> tuple[str, int] | None:
    return deepest_setup_site(
        exc,
        package_import_site_ranges(inventory_code, validation, walk_imports, hash_file),
        max_offset=MAX_PACKAGE_OFFSET,
    )


def namespace_creation_failure_site(
    exc: BaseException, creator: Any, namespace: Any, contract: Any, worker: Any
) -> tuple[str, int] | None:
    return deepest_setup_site(
        exc,
        namespace_creation_site_ranges(creator, namespace, contract, worker),
        max_offset=MAX_NAMESPACE_OFFSET,
    )
