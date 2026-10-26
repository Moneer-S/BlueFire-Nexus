"""Fixed, bounded code-site diagnostics for protected macOS setup failures."""

from __future__ import annotations

from typing import Any

NATIVE_STARTUP_EXIT_LABELS = {
    80: "runtime_supported_check",
    81: "initial_clock_or_deadline",
    82: "initial_descriptor_inventory",
    83: "readonly_descriptor",
    84: "credential_selection",
    85: "post_drop_descriptor_inventory",
    86: "initial_resource_validation",
    87: "channel_initialization",
    88: "initial_descriptor_inventory_query",
    89: "initial_descriptor_inventory_rows",
    90: "initial_descriptor_inventory_standard_streams",
    91: "initial_descriptor_inventory_missing_stdin",
    92: "initial_descriptor_inventory_missing_stdout",
    93: "initial_descriptor_inventory_missing_stderr",
    94: "initial_descriptor_inventory_missing_resource",
    95: "initial_descriptor_inventory_missing_control_channel",
    96: "initial_descriptor_inventory_unexpected_rows",
    97: "initial_descriptor_inventory_mixed_missing_stdin",
    98: "initial_descriptor_inventory_mixed_missing_stdout",
    99: "initial_descriptor_inventory_mixed_missing_stderr",
    100: "initial_descriptor_inventory_mixed_missing_resource",
    101: "initial_descriptor_inventory_mixed_missing_control_channel",
    102: "initial_descriptor_inventory_type_mismatch_stdin",
    103: "initial_descriptor_inventory_type_mismatch_stdout",
    104: "initial_descriptor_inventory_type_mismatch_stderr",
    105: "initial_descriptor_inventory_type_mismatch_resource",
    106: "initial_descriptor_inventory_type_mismatch_control_channel",
}
NATIVE_STARTUP_EXIT_ROLES = ("reader", "owner", "control")
NATIVE_STARTUP_STATUS_UNAVAILABLE_REASONS = frozenset(
    {
        "workers_not_closed",
        "not_settled",
        "cleanup_unknown",
        "not_started",
        "factory_not_entered",
        "process_count_mismatch",
        "proof_count_mismatch",
        "process_identity_mismatch",
        "worker_lock_busy",
        "returncode_unavailable",
        "returncode_invalid",
        "returncode_out_of_bounds",
    }
)


def native_startup_exit_label(value: Any) -> str | None:
    """Classify only the reserved nonzero native startup exits."""
    return NATIVE_STARTUP_EXIT_LABELS.get(value) if type(value) is int else None


def valid_native_startup_exits(value: Any) -> bool:
    """Validate a finite role-to-label diagnostic without lifecycle authority."""
    return (
        type(value) is dict
        and 0 < len(value) <= len(NATIVE_STARTUP_EXIT_ROLES)
        and all(
            type(role) is str
            and role in NATIVE_STARTUP_EXIT_ROLES
            and type(label) is str
            and label in NATIVE_STARTUP_EXIT_LABELS.values()
            for role, label in value.items()
        )
    )


def unavailable_native_startup_status(reason: str) -> dict[str, str]:
    if reason not in NATIVE_STARTUP_STATUS_UNAVAILABLE_REASONS:
        raise ValueError("unknown native startup status reason")
    return {"status": "unavailable", "reason": reason}


def native_startup_status_from_returncode(value: Any) -> dict[str, Any]:
    """Project one already-cached, bounded Popen status without inferring cause."""
    if type(value) is not int:
        return unavailable_native_startup_status(
            "returncode_unavailable" if value is None else "returncode_invalid"
        )
    if not -255 <= value <= 255:
        return unavailable_native_startup_status("returncode_out_of_bounds")
    label = native_startup_exit_label(value)
    if label is not None:
        return {"status": "reserved_stage_exit", "returncode": value, "label": label}
    if value == 0:
        return {"status": "clean_exit", "returncode": value}
    if value < 0:
        return {"status": "signal_termination", "returncode": value}
    return {"status": "other_exit", "returncode": value}


def valid_native_startup_status(value: Any) -> bool:
    if type(value) is not dict or type(value.get("status")) is not str:
        return False
    status = value["status"]
    if status == "unavailable":
        return (
            set(value) == {"status", "reason"}
            and type(value["reason"]) is str
            and value["reason"] in NATIVE_STARTUP_STATUS_UNAVAILABLE_REASONS
        )
    if set(value) not in (
        {"status", "returncode"},
        {"status", "returncode", "label"},
    ):
        return False
    code = value.get("returncode")
    if type(code) is not int or not -255 <= code <= 255:
        return False
    expected = native_startup_status_from_returncode(code)
    return value == expected


def valid_native_startup_statuses(value: Any) -> bool:
    return (
        type(value) is dict
        and 0 < len(value) <= len(NATIVE_STARTUP_EXIT_ROLES)
        and all(
            type(role) is str
            and role in NATIVE_STARTUP_EXIT_ROLES
            and valid_native_startup_status(status)
            for role, status in value.items()
        )
    )


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
    "namespace_worker_start": frozenset(range(133)),
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
MAX_NAMESPACE_OFFSET = 132
MAX_OFFSETS = {
    "package_import_custody": MAX_PACKAGE_OFFSET,
    "namespace_creation": MAX_NAMESPACE_OFFSET,
}

MAX_STARTUP_OBSERVATION_FAILURES = 255
STARTUP_OBSERVATION_SITES = frozenset(
    {
        "unknown",
        "worker_process_missing",
        "worker_process_not_retained",
        "worker_active_process_missing",
        "worker_process_indeterminate",
        "worker_nofork_proof_refresh_failed",
        "worker_consistency_changed",
        "peer_runtime_unsupported",
        "peer_uid_api_missing",
        "peer_euid_api_missing",
        "peer_real_uid_not_root",
        "peer_effective_uid_not_root",
        "peer_process_type_invalid",
        "peer_pid_type_invalid",
        "peer_pid_out_of_range",
        "peer_process_already_reaped",
        "peer_status_ownership_unavailable_initial",
        "peer_identity_keys_invalid",
        "peer_identity_value_invalid",
        "peer_uid_mismatch",
        "peer_gid_mismatch",
        "peer_expected_start_invalid",
        "peer_child_exited_before_query",
        "peer_bsd_query_failed",
        "peer_pid_mismatch",
        "peer_parent_mismatch",
        "peer_status_flags_missing",
        "peer_status_flags_invalid",
        "peer_status_invalid",
        "peer_observed_ids_mismatch",
        "peer_start_invalid",
        "peer_start_mismatch",
        "peer_process_reaped_after_query",
        "peer_status_ownership_unavailable_after_query",
        "peer_child_exited_after_query",
    }
)


def normalize_startup_observation_site(value: Any) -> str:
    """Return only a finite site label; arbitrary diagnostic strings are discarded."""
    if type(value) is str and value in STARTUP_OBSERVATION_SITES:
        return value
    return "unknown"


def record_startup_observation_failure(
    summary: tuple[int, str | None, str | None, bool], value: Any
) -> tuple[int, str | None, str | None, bool]:
    """Update a fixed first/last/count summary without retaining exception data."""
    if type(summary) is not tuple or len(summary) != 4:
        summary = (0, None, None, False)
    count, first, last, capped = summary
    site = normalize_startup_observation_site(value)
    if (
        type(count) is not int
        or not 0 <= count <= MAX_STARTUP_OBSERVATION_FAILURES
        or type(capped) is not bool
        or (first is not None and type(first) is not str)
        or (last is not None and type(last) is not str)
        or (count == 0 and (first is not None or last is not None or capped))
        or (count > 0 and (first is None or last is None))
    ):
        count, first, last, capped = 0, None, None, False
    if first is not None:
        first = normalize_startup_observation_site(first)
    next_count = min(count + 1, MAX_STARTUP_OBSERVATION_FAILURES)
    return (
        next_count,
        site if count == 0 else first,
        site,
        capped or next_count == MAX_STARTUP_OBSERVATION_FAILURES,
    )


def startup_observation_payload(value: Any) -> dict[str, Any] | None:
    """Validate the in-process summary before it crosses the CLI boundary."""
    if type(value) is not tuple or len(value) != 4:
        return None
    count, first, last, capped = value
    if (
        type(count) is not int
        or not 1 <= count <= MAX_STARTUP_OBSERVATION_FAILURES
        or type(capped) is not bool
        or capped != (count == MAX_STARTUP_OBSERVATION_FAILURES)
        or type(first) is not str
        or first not in STARTUP_OBSERVATION_SITES
        or type(last) is not str
        or last not in STARTUP_OBSERVATION_SITES
    ):
        return None
    return {
        "count": count,
        "count_capped": capped,
        "first_site": first,
        "last_site": last,
    }


def startup_observation_from_exception(exc: BaseException) -> dict[str, Any] | None:
    try:
        value = getattr(exc, "_safe_startup_observation_summary", None)
    except BaseException:
        return None
    return startup_observation_payload(value)


def valid_startup_observation_payload(value: Any) -> bool:
    if type(value) is not dict or set(value) != {
        "count",
        "count_capped",
        "first_site",
        "last_site",
    }:
        return False
    return (
        startup_observation_payload(
            (value["count"], value["first_site"], value["last_site"], value["count_capped"])
        )
        is not None
    )


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
            ((0, 132, "namespace_worker_start"),),
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
