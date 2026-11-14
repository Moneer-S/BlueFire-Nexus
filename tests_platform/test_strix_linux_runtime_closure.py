from __future__ import annotations

from typing import Any

import pytest

from bluefire import strix_linux_runtime_closure as closure
from bluefire.util import content_hash


def _sha(label: str) -> str:
    return content_hash({"fixture": label})


def _plan_document() -> dict[str, Any]:
    directories = set(closure._REQUIRED_DIRECTORIES)
    files = set(closure._REQUIRED_FILES)
    files.update(
        {
            "runtime/lib/python3.12/lib-dynload/_socket.so",
            "runtime/lib/python3.12/lib-dynload/_ctypes.cpython-312-x86_64-linux-gnu.so",
            "runtime/lib/python3.12/lib-dynload/_sha2.cpython-312-x86_64-linux-gnu.so",
            "runtime/lib/python3.12/site-packages/bluefire_strix_worker-1.dist-info/RECORD",
            "runtime/lib/python3.12/site-packages/strix_agent-1.7.0.dist-info/RECORD",
        }
    )
    for path in tuple(files):
        parts = path.split("/")[:-1]
        directories.update("/".join(parts[:index]) for index in range(1, len(parts) + 1))
    file_rows = []
    for path in sorted(files):
        mode = 0o555 if path in {"runtime/bin/python", "lib64/ld-linux-x86-64.so.2"} else 0o444
        file_rows.append(
            {
                "path": path,
                "mode": mode,
                "size": 1,
                "content_digest": _sha(path),
            }
        )
    directory_rows = [{"path": path, "mode": 0o555} for path in sorted(directories)]
    inventory = {
        "schema_version": "bluefire.strix-linux-runtime-inventory.v1",
        "directories": directory_rows,
        "files": file_rows,
        "total_bytes": len(file_rows),
    }
    boot_id = "11111111-2222-3333-4444-555555555555"
    root = {
        "schema_version": "bluefire.strix-runtime-source-root-identity.v1",
        "role": "strix-linux-runtime-closure-root",
        "st_dev": 44,
        "st_ino": 55,
        "mount_id": 66,
        "boot_id": boot_id,
    }
    by_path = {row["path"]: row for row in file_rows}
    return {
        "schema_version": closure.PLAN_SCHEMA,
        "source_revision": closure.SOURCE_REVISION,
        "package_digest": _sha("strix-wheel"),
        "strix_record_digest": by_path[
            "runtime/lib/python3.12/site-packages/strix_agent-1.7.0.dist-info/RECORD"
        ]["content_digest"],
        "worker_source_revision": "a" * 40,
        "worker_artifact_digest": _sha("worker-artifact"),
        "worker_record_digest": by_path[
            "runtime/lib/python3.12/site-packages/bluefire_strix_worker-1.dist-info/RECORD"
        ]["content_digest"],
        "cpython_artifact_digest": _sha("cpython-artifact"),
        "bootstrap_digest": by_path["bootstrap/worker.py"]["content_digest"],
        "lockdown_source_digest": by_path["bootstrap/worker_lockdown.py"][
            "content_digest"
        ],
        "seccomp_profile_digest": _sha("seccomp-profile"),
        "runtime_qualification_ref": _sha("runtime-qualification"),
        "preparation_manifest_ref": _sha("preparation-manifest"),
        "wheelhouse_ref": _sha("wheelhouse"),
        "elf_dependency_manifest_ref": _sha("elf-manifest"),
        "startup_overlay_ref": _sha("startup-overlay"),
        "controller_generation": 7,
        "closure_generation": 2,
        "platform": "linux",
        "machine": closure.MACHINE,
        "python_version": closure.PYTHON_VERSION,
        "root_st_dev": 44,
        "root_st_ino": 55,
        "source_mount_id": 66,
        "controller_boot_id": boot_id,
        "root_identity_digest": content_hash(root),
        "interpreter_digest": by_path["runtime/bin/python"]["content_digest"],
        "strix_entrypoint_digest": by_path["runtime/bin/strix"]["content_digest"],
        "directory_inventory": directory_rows,
        "file_inventory": file_rows,
        "inventory_digest": content_hash(inventory),
        "private_copy": True,
        "external_symlinks_absent": True,
        "hardlinks_absent": True,
        "special_files_absent": True,
        "host_credentials_absent": True,
        "docker_sockets_absent": True,
        "proc_absent_after_pivot": True,
    }


def test_plan_binds_fixed_site_independent_bootstrap_and_guest_projection() -> None:
    plan = closure.StrixLinuxRuntimeClosurePlan.from_mapping(_plan_document())

    assert plan.fixed_argv == (
        "/runtime/bin/python",
        "-I",
        "-S",
        "-B",
        "-X",
        "utf8",
        "/bootstrap/worker.py",
    )
    assert dict(plan.fixed_environment) == {
        "BLUEFIRE_STRIX_WORKER_LAUNCH_FILE": "/run/bluefire/launch.json",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/runtime/bin",
    }
    assert closure.FIXED_GUEST_PROJECTION["cwd"] == "/workspace"
    assert "dev" in closure.PRIVATE_OVERMOUNTS
    assert "workspace" in closure.PRIVATE_OVERMOUNTS
    assert plan.plan_ref == content_hash(plan.to_dict())


@pytest.mark.parametrize(
    ("path", "field"),
    [
        ("bootstrap/worker.py", "bootstrap_digest"),
        ("bootstrap/worker_lockdown.py", "lockdown_source_digest"),
        (
            "runtime/lib/python3.12/site-packages/strix_agent-1.7.0.dist-info/RECORD",
            "strix_record_digest",
        ),
        (
            "runtime/lib/python3.12/site-packages/bluefire_strix_worker-1.dist-info/RECORD",
            "worker_record_digest",
        ),
    ],
)
def test_plan_rejects_provenance_substitution(path: str, field: str) -> None:
    document = _plan_document()
    row = next(item for item in document["file_inventory"] if item["path"] == path)
    row["content_digest"] = _sha("substitution")
    document["inventory_digest"] = content_hash(
        {
            "schema_version": "bluefire.strix-linux-runtime-inventory.v1",
            "directories": document["directory_inventory"],
            "files": document["file_inventory"],
            "total_bytes": sum(item["size"] for item in document["file_inventory"]),
        }
    )

    with pytest.raises(closure.StrixLinuxRuntimeClosureError):
        closure.StrixLinuxRuntimeClosurePlan.from_mapping(document)

    assert field in document


def test_plan_rejects_python_startup_hook_and_private_mount_content() -> None:
    for path in (
        "runtime/lib/python3.12/site-packages/ambient.pth",
        "home/worker/.aws/credentials",
    ):
        document = _plan_document()
        document["file_inventory"].append(
            {"path": path, "mode": 0o444, "size": 0, "content_digest": _sha(path)}
        )
        document["file_inventory"].sort(key=lambda item: item["path"])
        document["inventory_digest"] = content_hash(
            {
                "schema_version": "bluefire.strix-linux-runtime-inventory.v1",
                "directories": document["directory_inventory"],
                "files": document["file_inventory"],
                "total_bytes": sum(item["size"] for item in document["file_inventory"]),
            }
        )
        with pytest.raises(closure.StrixLinuxRuntimeClosureError):
            closure.StrixLinuxRuntimeClosurePlan.from_mapping(document)


def test_zero_byte_package_marker_is_valid_but_unreviewed_executable_is_not() -> None:
    marker = closure.RuntimeFile.from_mapping(
        {
            "path": "runtime/lib/python3.12/site-packages/strix/py.typed",
            "mode": 0o444,
            "size": 0,
            "content_digest": _sha("empty"),
        }
    )
    assert marker.size == 0
    with pytest.raises(closure.StrixLinuxRuntimeClosureError):
        closure.RuntimeFile.from_mapping(
            {
                "path": "runtime/bin/unreviewed",
                "mode": 0o555,
                "size": 1,
                "content_digest": _sha("unreviewed"),
            }
        )


def test_plan_refuses_full_bluefire_product_wheel_in_worker_closure() -> None:
    document = _plan_document()
    directory = "runtime/lib/python3.12/site-packages/bluefire_nexus-3.0.dist-info"
    document["directory_inventory"].append({"path": directory, "mode": 0o555})
    document["directory_inventory"].sort(key=lambda item: item["path"])
    document["file_inventory"].append(
        {
            "path": f"{directory}/RECORD",
            "mode": 0o444,
            "size": 1,
            "content_digest": _sha("full-product-record"),
        }
    )
    document["file_inventory"].sort(key=lambda item: item["path"])
    document["inventory_digest"] = content_hash(
        {
            "schema_version": "bluefire.strix-linux-runtime-inventory.v1",
            "directories": document["directory_inventory"],
            "files": document["file_inventory"],
            "total_bytes": sum(item["size"] for item in document["file_inventory"]),
        }
    )

    with pytest.raises(closure.StrixLinuxRuntimeClosureError):
        closure.StrixLinuxRuntimeClosurePlan.from_mapping(document)
