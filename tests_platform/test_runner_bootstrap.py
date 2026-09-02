from __future__ import annotations

import copy
import hashlib
import json
import os
import stat
import subprocess  # nosec B404
import sys
from pathlib import Path
from typing import Any, BinaryIO, Mapping, Sequence

import pytest

import tools.stage_native_runner as stage_native_runner_module
from bluefire import __version__
from bluefire.runner_bootstrap import (
    ACTION_SDK_VERSION,
    INVENTORY_SCHEMA_VERSION,
    MANIFEST_FILENAME,
    MANIFEST_SCHEMA_VERSION,
    RECEIPT_PROTOCOL_VERSION,
    RUNNER_BINARY_ENV,
    RUNNER_ID,
    SANDBOX_ROOT_ENV,
    RunnerBootstrapError,
    RunnerPackageManifest,
    bootstrap_runner,
    load_runner_manifest,
    parse_runner_manifest,
    validate_runner_inventory,
)
from bluefire.runner_client import RunnerTransportError, canonical_runner_inventory
from bluefire.runner_inventory import BUILTIN_RUNNER_ACTION_VERSIONS
from tools.stage_native_runner import stage_native_runner

PRODUCT_VERSION = __version__
PLATFORM = "windows"
ARCHITECTURE = "x86_64"
FILENAME = "bluefire-runner.exe"
WHEEL_TAG = "win_amd64"


def _fake_pe(*, architecture: str = ARCHITECTURE) -> bytes:
    machine = {"x86_64": 0x8664, "aarch64": 0xAA64}[architecture]
    payload = bytearray(256)
    payload[:2] = b"MZ"
    payload[0x3C:0x40] = (128).to_bytes(4, "little")
    payload[128:132] = b"PE\0\0"
    payload[132:134] = machine.to_bytes(2, "little")
    return bytes(payload)


def _fake_native(platform_name: str, *, architecture: str = ARCHITECTURE) -> bytes:
    if platform_name == "windows":
        return _fake_pe(architecture=architecture)
    payload = bytearray(256)
    if platform_name == "linux":
        payload[:6] = b"\x7fELF\x02\x01"
        machine = {"x86_64": 62, "aarch64": 183}[architecture]
        payload[18:20] = machine.to_bytes(2, "little")
    else:
        payload[:4] = b"\xcf\xfa\xed\xfe"
        machine = {"x86_64": 0x01000007, "aarch64": 0x0100000C}[architecture]
        payload[4:8] = machine.to_bytes(4, "little")
    return bytes(payload)


def test_runner_transport_constructor_needs_only_the_standard_library(tmp_path: Path) -> None:
    source_root = Path(__file__).resolve().parents[1]
    completed = subprocess.run(  # nosec B603
        [
            sys.executable,
            "-S",
            "-B",
            "-c",
            (
                "import sys; from pathlib import Path; "
                "from bluefire.runner_client import SubprocessRustRunner; "
                "runner = SubprocessRustRunner(Path(sys.executable).resolve(), "
                "Path(sys.argv[1]).resolve()); "
                "assert 'bluefire.runner_trust' not in sys.modules; "
                "assert runner.runner_binary.is_file()"
            ),
            str(tmp_path / "runner-work"),
        ],
        cwd=source_root,
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )

    assert completed.returncode == 0, completed.stderr


def test_private_directory_guard_needs_only_the_standard_library(tmp_path: Path) -> None:
    source_root = Path(__file__).resolve().parents[1]
    completed = subprocess.run(  # nosec B603
        [
            sys.executable,
            "-S",
            "-B",
            "-c",
            (
                "import sys; from pathlib import Path; "
                "from bluefire.runner_private_files import _PinnedPrivateDirectory; "
                "root = Path(sys.argv[1]).resolve(); root.mkdir(); "
                "guard = _PinnedPrivateDirectory(root); "
                "guard.__enter__(); guard.close(); "
                "assert 'bluefire.runner_trust' not in sys.modules"
            ),
            str(tmp_path / "private-root"),
        ],
        cwd=source_root,
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )

    assert completed.returncode == 0, completed.stderr


def _manifest(payload: bytes | None = None) -> RunnerPackageManifest:
    payload = _fake_pe() if payload is None else payload
    return RunnerPackageManifest(
        product_version=PRODUCT_VERSION,
        runner_version=PRODUCT_VERSION,
        platform=PLATFORM,
        architecture=ARCHITECTURE,
        filename=FILENAME,
        size=len(payload),
        sha256=hashlib.sha256(payload).hexdigest(),
        wheel_platform_tag=WHEEL_TAG,
    )


def _inventory(**changes: Any) -> Mapping[str, Any]:
    value: dict[str, Any] = {
        "schema_version": INVENTORY_SCHEMA_VERSION,
        "runner_id": RUNNER_ID,
        "runner_version": PRODUCT_VERSION,
        "action_sdk_version": ACTION_SDK_VERSION,
        "receipt_protocol": RECEIPT_PROTOCOL_VERSION,
        "platform": PLATFORM,
        "actions": [
            {
                "schema_version": ACTION_SDK_VERSION,
                "action_id": action_id,
                "action_version": action_version,
                "readiness": "ready",
            }
            for action_id, action_version in BUILTIN_RUNNER_ACTION_VERSIONS.items()
        ],
    }
    value.update(changes)
    return value


def _corrupt_inventory(corruption: str) -> Mapping[str, Any]:
    value = copy.deepcopy(dict(_inventory()))
    actions = value["actions"]
    assert isinstance(actions, list)
    if corruption == "empty":
        actions.clear()
    elif corruption == "missing":
        actions.pop()
    elif corruption == "extra":
        actions.append(
            {
                "schema_version": ACTION_SDK_VERSION,
                "action_id": "sandbox.unreviewed.v1",
                "action_version": "1.0.0",
                "readiness": "ready",
            }
        )
    elif corruption == "duplicate":
        actions.append(copy.deepcopy(actions[0]))
    elif corruption == "wrong_version":
        actions[0]["action_version"] = "9.0.0"
    elif corruption == "not_ready":
        actions[0]["readiness"] = "structural"
    elif corruption == "missing_action_schema":
        actions[0].pop("schema_version")
    else:
        canonical = copy.deepcopy(dict(canonical_runner_inventory(value)))
        canonical_actions = canonical["actions"]
        assert isinstance(canonical_actions, list)
        if corruption == "missing_source_digest":
            canonical.pop("source_digest")
        elif corruption == "malformed_source_digest":
            canonical["source_digest"] = "sha256:invalid"
        elif corruption == "missing_contract_digest":
            canonical_actions[0].pop("contract_digest")
        elif corruption == "malformed_contract_digest":
            canonical_actions[0]["contract_digest"] = "sha256:invalid"
        else:  # pragma: no cover - guarded by the parametrization above.
            raise AssertionError(f"unknown inventory corruption: {corruption}")
        return canonical
    return value


def _resource_root(tmp_path: Path, payload: bytes | None = None) -> Path:
    payload = _fake_pe() if payload is None else payload
    root = tmp_path / "resources"
    root.mkdir()
    (root / FILENAME).write_bytes(payload)
    (root / MANIFEST_FILENAME).write_text(
        json.dumps(_manifest(payload).to_dict(), sort_keys=True),
        encoding="utf-8",
    )
    return root


def test_packaged_runner_bootstrap_is_atomic_private_and_path_safe(tmp_path: Path) -> None:
    resources = _resource_root(tmp_path)
    managed = tmp_path / "managed"

    result = bootstrap_runner(
        environ={},
        resource_root=resources,
        managed_root=managed,
        product_version=PRODUCT_VERSION,
        platform_name=PLATFORM,
        architecture=ARCHITECTURE,
        inventory_probe=lambda _binary: _inventory(),
    )

    assert result.source == "packaged"
    assert result.managed_binary is True
    assert result.managed_sandbox is True
    assert result.binary_path.read_bytes() == (resources / FILENAME).read_bytes()
    assert result.sandbox_path.is_dir()
    assert not list(managed.rglob("*.tmp"))
    if os.name != "nt":
        assert stat.S_IMODE(result.binary_path.stat().st_mode) == 0o700
        assert stat.S_IMODE(managed.stat().st_mode) == 0o700

    serialized = json.dumps(result.public_status(), sort_keys=True)
    assert str(tmp_path) not in serialized
    assert str(tmp_path) not in repr(result)
    assert result.public_status()["artifact"] == {
        "managed": True,
        "size": _manifest().size,
        "sha256": "sha256:" + _manifest().sha256,
        "wheel_platform_tag": WHEEL_TAG,
    }


def test_bootstrap_refuses_tampered_source_without_installing_it(tmp_path: Path) -> None:
    resources = _resource_root(tmp_path)
    (resources / FILENAME).write_bytes(b"tampered")

    with pytest.raises(RunnerBootstrapError) as refused:
        bootstrap_runner(
            environ={},
            resource_root=resources,
            managed_root=tmp_path / "managed",
            product_version=PRODUCT_VERSION,
            platform_name=PLATFORM,
            architecture=ARCHITECTURE,
            inventory_probe=lambda _binary: _inventory(),
        )

    assert "integrity" in str(refused.value).casefold()
    assert str(tmp_path) not in str(refused.value)
    assert not list((tmp_path / "managed").rglob(FILENAME))


def test_bootstrap_rechecks_integrity_after_health_probe(tmp_path: Path) -> None:
    resources = _resource_root(tmp_path)

    def corrupt_after_copy(binary: Path) -> Mapping[str, Any]:
        binary.write_bytes(b"changed after atomic copy")
        return _inventory()

    with pytest.raises(RunnerBootstrapError, match="changed during health verification"):
        bootstrap_runner(
            environ={},
            resource_root=resources,
            managed_root=tmp_path / "managed",
            product_version=PRODUCT_VERSION,
            platform_name=PLATFORM,
            architecture=ARCHITECTURE,
            inventory_probe=corrupt_after_copy,
        )


@pytest.mark.parametrize(
    ("section", "field", "value"),
    [
        ("root", "schema_version", "bluefire.native-runner-package.v2"),
        ("product", "name", "another-product"),
        ("product", "version", "9.9.9"),
        ("runner", "id", "different-runner.v1"),
        ("runner", "version", "9.9.9"),
        ("runner", "inventory_schema", "bluefire.runner-inventory.v2"),
        ("runner", "action_sdk_version", "bluefire.runner-action-sdk.v2"),
        ("runner", "receipt_protocol", "bluefire.runner-receipt-wal.v1"),
        ("artifact", "platform", "linux"),
        ("artifact", "architecture", "aarch64"),
        ("artifact", "wheel_platform_tag", "any"),
        ("artifact", "sha256", "A" * 64),
    ],
)
def test_manifest_refuses_incompatible_or_invalid_contracts(
    section: str,
    field: str,
    value: str,
) -> None:
    document = copy.deepcopy(_manifest().to_dict())
    target = document if section == "root" else document[section]
    target[field] = value

    with pytest.raises(RunnerBootstrapError):
        parse_runner_manifest(
            document,
            product_version=PRODUCT_VERSION,
            platform_name=PLATFORM,
            architecture=ARCHITECTURE,
        )


def test_manifest_is_strict_and_duplicate_json_keys_are_refused(tmp_path: Path) -> None:
    document = _manifest().to_dict()
    document["unexpected"] = True
    with pytest.raises(RunnerBootstrapError, match="manifest is invalid"):
        parse_runner_manifest(
            document,
            product_version=PRODUCT_VERSION,
            platform_name=PLATFORM,
            architecture=ARCHITECTURE,
        )

    root = tmp_path / "resources"
    root.mkdir()
    (root / MANIFEST_FILENAME).write_text(
        '{"schema_version":"%s","schema_version":"%s"}'
        % (MANIFEST_SCHEMA_VERSION, MANIFEST_SCHEMA_VERSION),
        encoding="utf-8",
    )
    with pytest.raises(RunnerBootstrapError, match="manifest is invalid"):
        load_runner_manifest(
            resource_root=root,
            product_version=PRODUCT_VERSION,
            platform_name=PLATFORM,
            architecture=ARCHITECTURE,
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("runner_id", "another-runner.v1"),
        ("runner_version", "0.2.0"),
        ("action_sdk_version", "bluefire.runner-action-sdk.v2"),
        ("receipt_protocol", "bluefire.runner-receipt-wal.v1"),
        ("platform", "linux"),
    ],
)
def test_inventory_must_match_manifest_compatibility(field: str, value: str) -> None:
    with pytest.raises(RunnerBootstrapError, match="incompatibility"):
        validate_runner_inventory(_inventory(**{field: value}), _manifest())


@pytest.mark.parametrize(
    "corruption",
    [
        "empty",
        "missing",
        "extra",
        "duplicate",
        "wrong_version",
        "not_ready",
        "missing_action_schema",
        "missing_source_digest",
        "malformed_source_digest",
        "missing_contract_digest",
        "malformed_contract_digest",
    ],
)
def test_inventory_requires_the_exact_ready_versioned_builtin_contracts(
    corruption: str,
) -> None:
    inventory = _corrupt_inventory(corruption)

    with pytest.raises(RunnerBootstrapError, match="invalid inventory"):
        validate_runner_inventory(inventory, _manifest())


def test_environment_override_is_explicit_and_sandbox_still_has_managed_fallback(
    tmp_path: Path,
) -> None:
    override = tmp_path / FILENAME
    override.write_bytes(_fake_pe())

    result = bootstrap_runner(
        environ={RUNNER_BINARY_ENV: str(override)},
        managed_root=tmp_path / "managed",
        product_version=PRODUCT_VERSION,
        platform_name=PLATFORM,
        architecture=ARCHITECTURE,
        inventory_probe=lambda binary: (
            _inventory() if binary == override.resolve(strict=True) else {}
        ),
    )

    assert result.source == "environment_override"
    assert result.managed_binary is False
    assert result.binary_path == override.resolve(strict=True)
    assert result.managed_sandbox is True
    assert result.public_status()["artifact"]["wheel_platform_tag"] is None
    assert str(override) not in json.dumps(result.public_status())


def test_environment_sandbox_override_remains_an_advanced_unmanaged_path(
    tmp_path: Path,
) -> None:
    resources = _resource_root(tmp_path)
    sandbox = tmp_path / "operator-sandbox"

    result = bootstrap_runner(
        environ={SANDBOX_ROOT_ENV: str(sandbox)},
        resource_root=resources,
        managed_root=tmp_path / "managed",
        product_version=PRODUCT_VERSION,
        platform_name=PLATFORM,
        architecture=ARCHITECTURE,
        inventory_probe=lambda _binary: _inventory(),
    )

    assert result.sandbox_path == sandbox.resolve(strict=True)
    assert result.managed_sandbox is False
    assert str(sandbox) not in json.dumps(result.public_status())


def test_staging_helper_writes_only_verified_platform_specific_assets(tmp_path: Path) -> None:
    source_root = tmp_path / "source"
    source_root.mkdir()
    runner = source_root / FILENAME
    runner.write_bytes(_fake_pe())
    output = tmp_path / "stage"
    output.mkdir()

    manifest = stage_native_runner(
        runner.resolve(),
        output,
        platform_name=PLATFORM,
        architecture=ARCHITECTURE,
        product_version=PRODUCT_VERSION,
        inventory=_inventory(),
    )

    assert manifest.wheel_platform_tag == WHEEL_TAG
    assert (output / FILENAME).read_bytes() == runner.read_bytes()
    assert json.loads((output / MANIFEST_FILENAME).read_text(encoding="utf-8")) == (
        manifest.to_dict()
    )
    assert not list(output.glob("*.tmp"))


@pytest.mark.parametrize(
    ("platform_name", "filename", "wheel_tag"),
    [
        ("windows", "bluefire-runner.exe", "win_amd64"),
        ("linux", "bluefire-runner", "linux_x86_64"),
        ("macos", "bluefire-runner", "macosx_11_0_x86_64"),
    ],
)
def test_staging_binds_platform_architecture_version_inventory_and_hash(
    tmp_path: Path,
    platform_name: str,
    filename: str,
    wheel_tag: str,
) -> None:
    source_root = tmp_path / "source"
    source_root.mkdir()
    runner = source_root / filename
    payload = _fake_native(platform_name)
    runner.write_bytes(payload)
    output = tmp_path / "stage"

    manifest = stage_native_runner(
        runner.resolve(),
        output,
        platform_name=platform_name,
        architecture=ARCHITECTURE,
        product_version=PRODUCT_VERSION,
        inventory=_inventory(platform=platform_name),
    )

    assert manifest.platform == platform_name
    assert manifest.architecture == ARCHITECTURE
    assert manifest.product_version == PRODUCT_VERSION
    assert manifest.runner_version == PRODUCT_VERSION
    assert manifest.wheel_platform_tag == wheel_tag
    assert manifest.size == len(payload)
    assert manifest.sha256 == hashlib.sha256(payload).hexdigest()
    assert (output / filename).read_bytes() == payload
    assert json.loads((output / MANIFEST_FILENAME).read_bytes()) == manifest.to_dict()


@pytest.mark.parametrize(
    "diagnostic",
    (
        "Darwin watchdog runtime could not be staged",
        "Linux private process containment is unavailable",
    ),
)
def test_inventory_probe_surfaces_a_safe_transport_diagnostic(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    diagnostic: str,
) -> None:
    class FailingRunner:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def inventory(self) -> Mapping[str, Any]:
            raise RunnerTransportError(diagnostic)

    monkeypatch.setattr(stage_native_runner_module, "SubprocessRustRunner", FailingRunner)

    with pytest.raises(RunnerBootstrapError) as caught:
        stage_native_runner_module._probe_inventory(tmp_path / "bluefire-runner")

    assert str(caught.value) == f"The native runner inventory probe failed: {diagnostic}"


def test_inventory_probe_redacts_an_unsafe_transport_diagnostic(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private_detail = "failed at C:" + r"\Users\private-user\runner.exe"

    class FailingRunner:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def inventory(self) -> Mapping[str, Any]:
            raise RunnerTransportError(private_detail)

    monkeypatch.setattr(stage_native_runner_module, "SubprocessRustRunner", FailingRunner)

    with pytest.raises(RunnerBootstrapError) as caught:
        stage_native_runner_module._probe_inventory(tmp_path / "bluefire-runner")

    assert str(caught.value) == (
        "The native runner inventory probe failed: "
        "runner transport failed without a safe diagnostic"
    )
    assert private_detail not in str(caught.value)
    assert caught.value.__cause__ is None


def test_staging_preserves_package_tree_and_replaces_only_generated_pair(tmp_path: Path) -> None:
    source_root = tmp_path / "source"
    source_root.mkdir()
    runner = source_root / FILENAME
    runner.write_bytes(_fake_pe())
    output = tmp_path / "stage"
    output.mkdir()
    initializer = output / "__init__.py"
    initializer.write_bytes(b"package marker\n")
    nested = output / "linux-x86_64"
    nested.mkdir()
    nested_marker = nested / "artifact.lock"
    nested_marker.write_bytes(b"preserve exact nested content\n")
    superseded_runner = output / "bluefire-runner"
    superseded_runner.write_bytes(b"superseded generated content")
    (output / MANIFEST_FILENAME).write_bytes(b"superseded manifest\n")

    manifest = stage_native_runner(
        runner.resolve(),
        output,
        platform_name=PLATFORM,
        architecture=ARCHITECTURE,
        product_version=PRODUCT_VERSION,
        inventory=_inventory(),
    )

    assert initializer.read_bytes() == b"package marker\n"
    assert nested_marker.read_bytes() == b"preserve exact nested content\n"
    assert not superseded_runner.exists()
    assert (output / FILENAME).read_bytes() == runner.read_bytes()
    assert json.loads((output / MANIFEST_FILENAME).read_bytes()) == manifest.to_dict()
    assert not list(output.glob("*.tmp"))
    assert not list(tmp_path.glob(".stage.bluefire-native-*"))


def test_staging_probes_the_private_single_link_copy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_root = tmp_path / "source"
    source_root.mkdir()
    runner = source_root / FILENAME
    runner.write_bytes(_fake_pe())
    os.link(runner, source_root / "cargo-hardlink.exe")
    output = tmp_path / "stage"
    output.mkdir()
    observed: list[Path] = []

    def probe(binary: Path) -> Mapping[str, Any]:
        observed.append(binary)
        assert binary != runner
        assert binary.stat(follow_symlinks=False).st_nlink == 1
        return _inventory()

    monkeypatch.setattr(stage_native_runner_module, "_probe_inventory", probe)

    stage_native_runner(
        runner.resolve(),
        output,
        platform_name=PLATFORM,
        architecture=ARCHITECTURE,
        product_version=PRODUCT_VERSION,
    )

    assert len(observed) == 1
    assert observed[0].parent.name.startswith(".stage.bluefire-native-stage-")
    assert (output / FILENAME).stat(follow_symlinks=False).st_nlink == 1


def test_staging_preserves_a_foreign_destination_that_wins_the_publish_race(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_root = tmp_path / "source"
    source_root.mkdir()
    runner = source_root / FILENAME
    runner.write_bytes(_fake_pe())
    output = tmp_path / "stage"
    output.mkdir()
    original_publish = stage_native_runner_module._atomic_rename_no_replace
    publication_calls = 0
    winner_identity: os.stat_result | None = None

    def publish_after_foreign_winner(source: Path, destination: Path) -> None:
        nonlocal publication_calls, winner_identity
        publication_calls += 1
        if publication_calls == 2:
            destination.mkdir()
            winner_identity = destination.stat(follow_symlinks=False)
        original_publish(source, destination)

    monkeypatch.setattr(
        stage_native_runner_module,
        "_atomic_rename_no_replace",
        publish_after_foreign_winner,
    )

    with pytest.raises(RunnerBootstrapError, match="could not be staged safely"):
        stage_native_runner(
            runner.resolve(),
            output,
            platform_name=PLATFORM,
            architecture=ARCHITECTURE,
            product_version=PRODUCT_VERSION,
            inventory=_inventory(),
        )

    assert winner_identity is not None
    assert os.path.samestat(output.stat(follow_symlinks=False), winner_identity)
    assert not list(output.iterdir())
    assert not list(tmp_path.glob(".stage.bluefire-native-*"))


def test_staging_preserves_foreign_content_added_before_destination_claim(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_root = tmp_path / "source"
    source_root.mkdir()
    runner = source_root / FILENAME
    runner.write_bytes(_fake_pe())
    output = tmp_path / "stage"
    output.mkdir()
    marker = output / "foreign-content"
    original_publish = stage_native_runner_module._atomic_rename_no_replace
    publication_calls = 0

    def claim_after_foreign_write(source: Path, destination: Path) -> None:
        nonlocal publication_calls
        publication_calls += 1
        if publication_calls == 1:
            marker.write_bytes(b"preserve me")
        original_publish(source, destination)

    monkeypatch.setattr(
        stage_native_runner_module,
        "_atomic_rename_no_replace",
        claim_after_foreign_write,
    )

    with pytest.raises(RunnerBootstrapError, match="changed during publication"):
        stage_native_runner(
            runner.resolve(),
            output,
            platform_name=PLATFORM,
            architecture=ARCHITECTURE,
            product_version=PRODUCT_VERSION,
            inventory=_inventory(),
        )

    assert marker.read_bytes() == b"preserve me"
    assert not (output / FILENAME).exists()
    assert not (output / MANIFEST_FILENAME).exists()
    assert not list(tmp_path.glob(".stage.bluefire-native-*"))


def test_staging_publication_failure_restores_nonempty_destination_without_partial_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_root = tmp_path / "source"
    source_root.mkdir()
    runner = source_root / FILENAME
    runner.write_bytes(_fake_pe())
    output = tmp_path / "stage"
    output.mkdir()
    initializer = output / "__init__.py"
    initializer.write_bytes(b"preserve the package marker\n")
    nested = output / "linux-x86_64"
    nested.mkdir()
    nested_marker = nested / "artifact.lock"
    nested_marker.write_bytes(b"preserve the nested artifact\n")
    original_publish = stage_native_runner_module._atomic_rename_no_replace
    publication_calls = 0

    def fail_publication(source: Path, destination: Path) -> None:
        nonlocal publication_calls
        publication_calls += 1
        if publication_calls == 2:
            raise OSError("simulated publication failure")
        original_publish(source, destination)

    monkeypatch.setattr(
        stage_native_runner_module,
        "_atomic_rename_no_replace",
        fail_publication,
    )

    with pytest.raises(RunnerBootstrapError, match="could not be staged safely"):
        stage_native_runner(
            runner.resolve(),
            output,
            platform_name=PLATFORM,
            architecture=ARCHITECTURE,
            product_version=PRODUCT_VERSION,
            inventory=_inventory(),
        )

    assert output.is_dir()
    assert initializer.read_bytes() == b"preserve the package marker\n"
    assert nested_marker.read_bytes() == b"preserve the nested artifact\n"
    assert sorted(path.relative_to(output) for path in output.rglob("*")) == [
        Path("__init__.py"),
        Path("linux-x86_64"),
        Path("linux-x86_64/artifact.lock"),
    ]
    assert not list(tmp_path.glob(".stage.bluefire-native-*"))


def test_staging_reports_mutated_superseded_tree_without_removing_foreign_content(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_root = tmp_path / "source"
    source_root.mkdir()
    runner = source_root / FILENAME
    runner.write_bytes(_fake_pe())
    output = tmp_path / "stage"
    output.mkdir()
    (output / "__init__.py").write_bytes(b"package marker\n")
    original_cleanup = stage_native_runner_module._remove_snapshot_tree
    observed_reservation: Path | None = None

    def mutate_before_cleanup(
        path: Path,
        expected_root: os.stat_result,
        expected_entries: Sequence[stage_native_runner_module._TreeEntry],
    ) -> bool:
        nonlocal observed_reservation
        observed_reservation = path
        (path / "foreign-race-winner").write_bytes(b"never remove me")
        return original_cleanup(path, expected_root, expected_entries)

    monkeypatch.setattr(
        stage_native_runner_module,
        "_remove_snapshot_tree",
        mutate_before_cleanup,
    )

    with pytest.raises(
        RunnerBootstrapError,
        match="superseded native runner tree could not be removed safely",
    ):
        stage_native_runner(
            runner.resolve(),
            output,
            platform_name=PLATFORM,
            architecture=ARCHITECTURE,
            product_version=PRODUCT_VERSION,
            inventory=_inventory(),
        )

    assert (output / FILENAME).read_bytes() == runner.read_bytes()
    assert (output / "__init__.py").read_bytes() == b"package marker\n"
    assert observed_reservation is not None
    assert (observed_reservation / "foreign-race-winner").read_bytes() == b"never remove me"


def test_staging_copy_failure_removes_owned_partial_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_root = tmp_path / "source"
    source_root.mkdir()
    runner = source_root / FILENAME
    runner.write_bytes(_fake_pe())
    output = tmp_path / "stage"
    output.mkdir()

    def fail_after_partial_copy(_source: BinaryIO, destination: BinaryIO) -> None:
        destination.write(b"partial owned bytes")
        raise OSError("simulated partial copy failure")

    monkeypatch.setattr(
        stage_native_runner_module.shutil,
        "copyfileobj",
        fail_after_partial_copy,
    )

    with pytest.raises(RunnerBootstrapError, match="could not be staged safely"):
        stage_native_runner(
            runner.resolve(),
            output,
            platform_name=PLATFORM,
            architecture=ARCHITECTURE,
            product_version=PRODUCT_VERSION,
            inventory=_inventory(),
        )

    assert output.is_dir()
    assert not list(output.iterdir())
    assert not list(tmp_path.glob(".stage.bluefire-native-*"))


def test_staging_refuses_a_non_authoritative_inventory_before_copy(tmp_path: Path) -> None:
    source_root = tmp_path / "source"
    source_root.mkdir()
    runner = source_root / FILENAME
    runner.write_bytes(_fake_pe())
    output = tmp_path / "stage"

    with pytest.raises(RunnerBootstrapError, match="invalid inventory"):
        stage_native_runner(
            runner.resolve(),
            output,
            platform_name=PLATFORM,
            architecture=ARCHITECTURE,
            product_version=PRODUCT_VERSION,
            inventory=_corrupt_inventory("duplicate"),
        )

    assert not (output / FILENAME).exists()
    assert not (output / MANIFEST_FILENAME).exists()
    assert not list(output.glob("*.tmp"))


def test_staging_refuses_mislabeled_executable_architecture(tmp_path: Path) -> None:
    source_root = tmp_path / "source"
    source_root.mkdir()
    runner = source_root / FILENAME
    runner.write_bytes(_fake_pe(architecture="aarch64"))

    with pytest.raises(RunnerBootstrapError, match="staging input"):
        stage_native_runner(
            runner.resolve(),
            tmp_path / "stage",
            platform_name=PLATFORM,
            architecture=ARCHITECTURE,
            product_version=PRODUCT_VERSION,
            inventory=_inventory(),
        )
