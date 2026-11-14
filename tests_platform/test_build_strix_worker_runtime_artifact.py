from __future__ import annotations

import csv
import hashlib
import io
import json
import sys
import zipfile
from pathlib import Path

import pytest

from tools import build_strix_worker_runtime_artifact as artifact


def _sources() -> dict[str, bytes]:
    rows = {
        "bluefire/strix_controlled_installed_worker.py": """
from . import strix_controlled_bootstrap
from . import strix_controlled_worker_launch
from . import strix_controlled_worker_rpc
""",
        "bluefire/strix_controlled_bootstrap.py": """
def _load(module_loader, name):
    return module_loader(name)
def run(module_loader):
    _load(module_loader, "bluefire.strix_controlled_backend")
    _load(module_loader, "strix.runtime.backends")
    _load(module_loader, "strix.interface.main")
""",
        "bluefire/strix_controlled_backend.py": """
from .util import content_hash
def run(module_loader):
    module_loader("agents.sandbox.session")
    module_loader("agents.sandbox.snapshot")
    module_loader("agents.sandbox.types")
""",
        "bluefire/strix_controlled_worker_launch.py": """
from . import strix_controlled_backend
from . import strix_controlled_bootstrap
from . import strix_controlled_worker_channel
from . import strix_controlled_worker_invocation
from . import strix_controlled_worker_packets
from . import strix_controlled_worker_rpc
""",
        "bluefire/strix_controlled_worker_channel.py": """
from . import strix_controlled_backend
from .util import canonical_json_bytes
""",
        "bluefire/strix_controlled_worker_invocation.py": """
from . import strix_adapter
from . import strix_controlled_backend
from . import strix_startup_overlay
from .util import content_hash
""",
        "bluefire/strix_controlled_worker_packets.py": "import asyncio\n",
        "bluefire/strix_controlled_worker_rpc.py": """
from . import strix_controlled_backend
from . import strix_controlled_worker_channel
from . import strix_controlled_worker_packets
from .util import content_hash
""",
        "bluefire/strix_adapter.py": """
from . import strix_policy_overlay
from .util import content_hash
""",
        "bluefire/strix_policy_overlay.py": "from importlib.resources import files\n",
        "bluefire/strix_startup_overlay.py": "from .util import content_hash\n",
        "bluefire/util.py": "import hashlib\nimport json\n",
    }
    return {path: rows[path].lstrip().encode("utf-8") for path in artifact.MODULE_PATHS}


def _resources() -> dict[str, bytes]:
    return {artifact.RESOURCE_PATHS[0]: b"reviewed prompt policy\n"}


def _build(tmp_path: Path, name: str) -> tuple[dict[str, object], bytes]:
    output = tmp_path / name
    result = artifact.build_artifact_from_sources(
        sources=_sources(),
        resources=_resources(),
        source_revision="a" * 40,
        product_version="3.0.0rc2",
        output_directory=output,
        stdlib_roots=frozenset(sys.stdlib_module_names),
    )
    return result, Path(str(result["artifact_path"])).read_bytes()


def _record_rows(payload: bytes) -> tuple[list[list[str]], dict[str, bytes]]:
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        members = {name: archive.read(name) for name in archive.namelist()}
    record_path = next(name for name in members if name.endswith(".dist-info/RECORD"))
    rows = list(csv.reader(io.StringIO(members[record_path].decode("utf-8"))))
    return rows, members


def test_dedicated_worker_wheel_is_deterministic_exact_and_record_bound(tmp_path: Path) -> None:
    first, first_bytes = _build(tmp_path, "first")
    second, second_bytes = _build(tmp_path, "second")
    assert first_bytes == second_bytes
    assert first["artifact_digest"] == "sha256:" + hashlib.sha256(first_bytes).hexdigest()
    assert first["production_ready"] is False
    assert first["entry_module"] == artifact.ENTRY_MODULE

    rows, members = _record_rows(first_bytes)
    names = tuple(sorted(members))
    assert names == tuple(members)
    assert "bluefire/__init__.py" not in members
    assert set(artifact.MODULE_PATHS).issubset(members)
    assert set(artifact.RESOURCE_PATHS).issubset(members)
    assert not any("bluefire_nexus" in name for name in names)
    manifest_path = str(first["manifest_path"])
    manifest = json.loads(members[manifest_path])
    assert set(manifest) == {
        "allowed_dynamic_imports",
        "distribution",
        "entry_module",
        "entrypoint_digest",
        "forbidden_distributions",
        "import_graph_digest",
        "module_inventory",
        "platform_tag",
        "python_abi",
        "required_installed_distributions",
        "requires_dist",
        "requires_python",
        "resource_inventory",
        "schema_version",
        "version",
        "wheel_tag",
        "worker_source_revision",
    }
    assert manifest["distribution"] == "bluefire-strix-worker"
    assert manifest["entry_module"] == artifact.ENTRY_MODULE
    assert manifest["entrypoint_digest"] == next(
        row["content_digest"]
        for row in manifest["module_inventory"]
        if row["path"] == "bluefire/strix_controlled_installed_worker.py"
    )
    assert manifest["requires_dist"] == list(artifact.REQUIRES_DIST)
    assert manifest["required_installed_distributions"] == [
        {"name": name, "version": version}
        for name, version in artifact.REQUIRED_INSTALLED_DISTRIBUTIONS
    ]
    assert manifest["forbidden_distributions"] == ["bluefire-nexus"]
    assert manifest["wheel_tag"] == "py3-none-any"
    assert (
        first["worker_record_digest"]
        == "sha256:"
        + hashlib.sha256(
            members[next(name for name in members if name.endswith(".dist-info/RECORD"))]
        ).hexdigest()
    )

    record_index = {row[0]: row[1:] for row in rows}
    assert set(record_index) == set(members)
    record_path = next(name for name in members if name.endswith(".dist-info/RECORD"))
    assert record_index[record_path] == ["", ""]
    for path, payload in members.items():
        if path == record_path:
            continue
        assert record_index[path][0] == artifact._record_hash(payload)
        assert record_index[path][1] == str(len(payload))


def test_worker_artifact_refuses_bluefire_import_outside_allowlist(tmp_path: Path) -> None:
    sources = _sources()
    sources["bluefire/strix_controlled_installed_worker.py"] += b"from . import product_store\n"
    with pytest.raises(artifact.StrixWorkerArtifactError, match="outside"):
        artifact.build_artifact_from_sources(
            sources=sources,
            resources=_resources(),
            source_revision="b" * 40,
            product_version="3.0.0rc2",
            output_directory=tmp_path / "bad-local",
            stdlib_roots=frozenset(sys.stdlib_module_names),
        )


def test_worker_artifact_refuses_dynamic_import_drift(tmp_path: Path) -> None:
    sources = _sources()
    sources["bluefire/strix_controlled_backend.py"] += b'module_loader("subprocess")\n'
    with pytest.raises(artifact.StrixWorkerArtifactError, match="dynamic import"):
        artifact.build_artifact_from_sources(
            sources=sources,
            resources=_resources(),
            source_revision="c" * 40,
            product_version="3.0.0rc2",
            output_directory=tmp_path / "bad-dynamic",
            stdlib_roots=frozenset(sys.stdlib_module_names),
        )


def test_full_product_dependency_set_is_incompatible_with_pinned_strix() -> None:
    with pytest.raises(artifact.StrixWorkerArtifactError, match="cryptography"):
        artifact.validate_locked_requirements(
            ("cryptography>=50,<51",),
            {"cryptography": "48.0.1"},
        )
    with pytest.raises(artifact.StrixWorkerArtifactError, match="pynacl"):
        artifact.validate_locked_requirements(
            ("PyNaCl>=1.5,<2",),
            {"cryptography": "48.0.1"},
        )
    assert (
        artifact.validate_locked_requirements(
            artifact.REQUIRES_DIST,
            artifact.LOCKED_RUNTIME_VERSIONS,
        )
        == artifact.REQUIRES_DIST
    )


def test_installed_distribution_digest_is_sorted_exact_and_forbids_product() -> None:
    rows = [
        {
            "name": name,
            "version": version,
            "metadata_digest": "sha256:" + character * 64,
            "record_digest": "sha256:" + character.upper().lower() * 64,
        }
        for (name, version), character in zip(
            artifact.REQUIRED_INSTALLED_DISTRIBUTIONS, "abc", strict=True
        )
    ]
    assert artifact.installed_distributions_digest(rows).startswith("sha256:")
    with pytest.raises(artifact.StrixWorkerArtifactError, match="sorted"):
        artifact.installed_distributions_digest(list(reversed(rows)))
    forbidden = [
        {
            "name": "bluefire-nexus",
            "version": "3.0.0rc2",
            "metadata_digest": "sha256:" + "d" * 64,
            "record_digest": "sha256:" + "e" * 64,
        }
    ]
    with pytest.raises(artifact.StrixWorkerArtifactError, match="forbidden"):
        artifact.installed_distributions_digest(forbidden)
