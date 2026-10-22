from __future__ import annotations

import ast
from pathlib import Path

import yaml

WORKFLOW = Path(__file__).parents[1] / ".github" / "workflows" / "native-assets.yml"
# Public GitHub Action commit pins, not credentials.
CHECKOUT_SHA = "d23441a48e516b6c34aea4fa41551a30e30af803"  # pragma: allowlist secret
SETUP_PYTHON_SHA = "ece7cb06caefa5fff74198d8649806c4678c61a1"  # pragma: allowlist secret
UPLOAD_ARTIFACT_SHA = "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"  # pragma: allowlist secret


def test_native_asset_workflow_is_manual_read_only_and_source_bound() -> None:
    workflow = yaml.load(WORKFLOW.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)

    assert workflow["on"] == {"workflow_dispatch": ""}
    assert workflow["permissions"] == {"contents": "read"}
    assert workflow["concurrency"]["cancel-in-progress"] == "false"
    assert set(workflow["jobs"]) == {"build"}

    job = workflow["jobs"]["build"]
    assert job["timeout-minutes"] == "30"
    matrix = job["strategy"]["matrix"]["include"]
    platforms = {(item["platform"], item["os"], item["target"]) for item in matrix}
    assert platforms == {
        ("windows", "windows-latest", "x86_64-pc-windows-msvc"),
        ("linux", "ubuntu-latest", "x86_64-unknown-linux-musl"),
    }
    binaries = {item["platform"]: item["binary"] for item in matrix}
    assert binaries == {
        "windows": "runner/target/release/bluefire-runner.exe",
        "linux": "runner/target/x86_64-unknown-linux-musl/release/bluefire-runner",
    }

    steps = job["steps"]
    checkout = next(step for step in steps if step["uses"].startswith("actions/checkout@"))
    assert checkout["uses"].split("@")[1].split()[0] == CHECKOUT_SHA
    assert checkout["with"]["ref"] == "${{ github.sha }}"
    assert checkout["with"]["persist-credentials"] == "false"
    assert not any("workflow_call" in step.get("run", "") for step in steps)

    assert any(
        step.get("uses", "").startswith(f"actions/setup-python@{SETUP_PYTHON_SHA}")
        for step in steps
    )
    upload = next(
        step for step in steps if step.get("uses", "").startswith("actions/upload-artifact@")
    )
    assert upload["uses"].split("@")[1].split()[0] == UPLOAD_ARTIFACT_SHA
    assert upload["with"]["retention-days"] == "7"
    assert upload["with"]["if-no-files-found"] == "error"

    commands = "\n".join(step.get("run", "") for step in steps)
    assert "tools/build_native_runner.py" in commands
    assert "tools/stage_native_runner.py" not in commands
    assert "pip install" not in commands
    assert "github.event.inputs" not in commands


def test_native_asset_receipt_is_versioned_and_allowlisted() -> None:
    workflow = yaml.load(WORKFLOW.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
    steps = workflow["jobs"]["build"]["steps"]
    windows_run = next(
        step["run"]
        for step in steps
        if step.get("name") == "Create binary and sanitized build receipt (Windows)"
    )
    linux_run = next(
        step["run"]
        for step in steps
        if step.get("name") == "Create binary and sanitized build receipt (Linux)"
    )
    windows_script = windows_run.split("$script = @'\n", 1)[1].split("\n'@", 1)[0]
    linux_script = linux_run.split("python - <<'PY'\n", 1)[1].split("\nPY", 1)[0]

    common_expected = {
        "schema_version",
        "source",
        "runner",
        "versions",
        "toolchain",
        "cargo_lock_sha256",
        "binary",
    }
    for script, expected in (
        (windows_script, common_expected),
        (linux_script, common_expected | {"inventory"}),
    ):
        parsed = ast.parse(script)
        receipt = next(
            node.value
            for node in parsed.body
            if isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Name) and target.id == "receipt" for target in node.targets
            )
        )
        assert isinstance(receipt, ast.Dict)
        keys = {ast.literal_eval(key) for key in receipt.keys}
        assert keys == expected
        nested = {
            ast.literal_eval(key): value
            for key, value in zip(receipt.keys, receipt.values, strict=True)
            if isinstance(key, ast.Constant)
        }
        nested_fields = {
            "source": {"commit", "tree"},
            "runner": {"os", "image", "architecture", "target"},
            "versions": {"product", "cargo_package"},
            "toolchain": {"rustc", "cargo"},
            "binary": {"filename", "bytes", "sha256"},
        }
        if "inventory" in expected:
            nested_fields["inventory"] = {"filename", "bytes", "sha256"}
        for key, allowed in nested_fields.items():
            child = nested[key]
            assert isinstance(child, ast.Dict)
            assert {ast.literal_eval(child_key) for child_key in child.keys} == allowed
        image = nested["runner"].values[1]
        assert isinstance(image, ast.Dict)
        assert {ast.literal_eval(key) for key in image.keys} == {"name", "version"}
        assert '["rustc", "--version"]' in script
        assert '["cargo", "--version"]' in script
        assert 'root / "runner/Cargo.lock"' in script
        assert 'root / "Cargo.lock"' not in script
    assert (WORKFLOW.parents[2] / "runner" / "Cargo.lock").is_file()


def test_linux_native_receipt_binds_bounded_host_produced_inventory() -> None:
    workflow = yaml.load(WORKFLOW.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
    step = next(
        step
        for step in workflow["jobs"]["build"]["steps"]
        if step.get("name") == "Create binary and sanitized build receipt (Linux)"
    )
    script = step["run"].split("python - <<'PY'\n", 1)[1].split("\nPY", 1)[0]
    parsed = ast.parse(script)

    assert "from bluefire.runner_client import SubprocessRustRunner" in script
    assert (
        "from bluefire.runner_bootstrap import build_runner_manifest, validate_runner_inventory"
        in script
    )
    assert "from bluefire.util import canonical_json_bytes" in script
    assert 'tempfile.TemporaryDirectory(prefix="bluefire-native-inventory-")' in script
    assert "shutil.copyfile(source, binary)\nos.chmod(binary, 0o700)" in script
    assert (
        script.index("os.chmod(binary, 0o700)")
        < script.index("manifest = build_runner_manifest(")
        < script.index("SubprocessRustRunner(")
    )
    probe = next(
        node
        for node in ast.walk(parsed)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "SubprocessRustRunner"
    )
    assert len(probe.args) == 2
    assert ast.unparse(probe.args[0]) == "binary.resolve(strict=True)"
    assert ast.unparse(probe.args[1]) == "Path(work_root)"
    assert {keyword.arg for keyword in probe.keywords} == {
        "timeout_seconds",
        "output_limit_bytes",
    }
    timeout = next(item.value for item in probe.keywords if item.arg == "timeout_seconds")
    output_limit = next(item.value for item in probe.keywords if item.arg == "output_limit_bytes")
    assert ast.literal_eval(timeout) == 10.0
    assert ast.unparse(output_limit) == "2 * 1024 * 1024"
    assert "validate_runner_inventory(inventory, manifest)" in script
    assert 'inventory_bytes = canonical_json_bytes(inventory) + b"\\n"' in script
    assert 'inventory_path = output / "runner-inventory.json"' in script
    assert 'inventory_path.open("xb")' in script
    assert '"inventory": {' in script
    assert '"bytes": len(inventory_bytes)' in script
    assert '"sha256": hashlib.sha256(inventory_bytes).hexdigest()' in script
    assert '"filename": inventory_path.name' in script

    upload = next(
        step
        for step in workflow["jobs"]["build"]["steps"]
        if step.get("uses", "").startswith("actions/upload-artifact@")
    )
    assert upload["with"]["path"] == "native-assets/"
