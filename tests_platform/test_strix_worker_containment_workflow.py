"""Keep the hosted worker-containment proof bounded, source-bound, and honest."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/strix-worker-containment.yml"
CHECKOUT = "actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803"
UPLOAD = "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"
SUMMARY = "${{ runner.temp }}/bluefire-worker-containment-evidence/public-summary.json"


def _workflow() -> dict:
    return yaml.load(WORKFLOW.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)


def _step(workflow: dict, name: str) -> dict:
    return next(step for step in workflow["jobs"]["qualify"]["steps"] if step["name"] == name)


def _assert_publication_boundary(workflow: dict) -> None:
    steps = workflow["jobs"]["qualify"]["steps"]
    uploads = [step for step in steps if "upload-artifact@" in step.get("uses", "")]
    assert len(uploads) == 1
    upload = uploads[0]
    assert upload["uses"] == UPLOAD
    assert upload["with"] == {
        "name": "bluefire-strix-worker-containment-mechanics-${{ github.sha }}",
        "path": SUMMARY,
        "if-no-files-found": "error",
        "retention-days": "1",
        "compression-level": "0",
        "overwrite": "false",
        "include-hidden-files": "false",
    }
    assert "raw-receipt" not in upload["with"]["path"]
    assert "target/release" not in upload["with"]["path"]


def test_workflow_is_one_bounded_credential_free_ubuntu_job() -> None:
    workflow = _workflow()
    assert workflow["on"] == {"workflow_dispatch": ""}
    assert workflow["permissions"] == {"contents": "read"}
    assert set(workflow["jobs"]) == {"qualify"}
    job = workflow["jobs"]["qualify"]
    assert job["runs-on"] == "ubuntu-24.04"
    assert job["timeout-minutes"] == "20"
    assert not any(key in job for key in ("container", "services", "permissions"))
    assert workflow["concurrency"] == {
        "group": "strix-worker-containment-${{ github.sha }}",
        "cancel-in-progress": "true",
    }
    checkout = _step(workflow, "Checkout exact BlueFire revision without retained credentials")
    assert checkout["uses"] == CHECKOUT
    assert checkout["with"] == {
        "ref": "${{ github.sha }}",
        "fetch-depth": "1",
        "persist-credentials": "false",
    }
    scripts = "\n".join(step.get("run", "") for step in job["steps"])
    for forbidden in ("docker ", "podman ", "curl ", "wget ", "gh ", "aws "):
        assert forbidden not in scripts
    assert "cargo build --locked --release" in scripts
    assert "cargo test" not in scripts, "this job is one fixed qualification, not a duplicate suite"


def test_workflow_fails_closed_and_runs_only_the_fixed_self_test() -> None:
    workflow = _workflow()
    preflight = _step(workflow, "Fail closed when required Linux primitives are unavailable")["run"]
    for requirement in (
        "cgroup2fs",
        "cgroup.controllers",
        "cpu memory pids",
        "kernel/seccomp/actions_avail",
        "memfd_create",
        "pidfd_open",
        "F_ADD_SEALS",
    ):
        assert requirement in preflight
    run = _step(workflow, "Run fixed harmless containment mechanics self-test")
    assert run["id"] == "containment-self-test"
    assert run["timeout-minutes"] == "5"
    script = run["run"]
    assert 'exec "$2" strix-worker-boundary-self-test' in script
    assert 'printf "%s %s\\n" "$$"' in script
    assert "installed-strix-runtime" in script
    assert "live-model-usefulness" in script
    assert 'receipt.get("installed_strix_qualified") is not False' in script
    assert 'receipt.get("pid_namespace_isolated") is not False' in script
    for proof in (
        "pidfd_owned_from_spawn",
        "same_tgid_thread_allowed",
        "clone3_enosys",
        "non_thread_clone_refused",
        "fork_refused",
        "vfork_refused",
        "exec_refused",
        "proc_absent",
        "controller_relay_allowed",
        "cancellation_identity_verified_with_spawn_pidfd",
        "cancelled_via_exact_cgroup_kill",
        "cgroup_empty_after_cancel",
        "sealed_input_fds_closed",
        "bootstrap_fd_closed",
        "fresh_address_space",
        "ambient_credential_absence_proven",
        "activation_eligible_for_fixed_harmless_worker",
        "helper_worker_executable_same",
        "worker_payload_identity_digest",
        "installed_strix_qualified",
    ):
        assert proof in script


def test_cleanup_is_unconditional_exact_and_residue_fails_qualification() -> None:
    workflow = _workflow()
    cleanup = _step(workflow, "Verify and clean exact ephemeral containment resources")
    assert cleanup["if"] == "${{ always() }}"
    script = cleanup["run"]
    assert "bluefire-strix-worker-selftest-*" in script
    assert "bluefire-strix-worker-root-*" in script
    assert "bluefire-strix-worker-uid-*.lease" in script
    assert "printf '1' | sudo tee \"$cgroup/cgroup.kill\"" in script
    assert "bluefire-strix-worker-root-$controller_pid" in script
    assert "comm -13" in script, "cleanup authority comes from the checked pre-attempt delta"
    assert "cmp -s" in script
    assert "< <(" not in script
    assert "controller_start" in script
    assert "expected_executable" in script
    assert "os.pidfd_open" in script
    assert "signal.pidfd_send_signal" in script
    assert "controller process remains after cancellation" in script
    assert 'test "$controller_status" = 0' in script
    assert 'test "$residue_before" = 0' in script
    assert 'test "$residue_after" = 0' in script
    assert "rm -rf" not in script


def test_only_sanitized_one_day_summary_can_be_uploaded() -> None:
    _assert_publication_boundary(_workflow())


@pytest.mark.parametrize(
    "path",
    (
        "${{ runner.temp }}/bluefire-worker-containment-evidence",
        "${{ runner.temp }}/bluefire-worker-containment-evidence/raw-receipt.json",
        "runner/target/release/bluefire-runner",
        ".",
    ),
)
def test_publication_boundary_rejects_raw_or_broad_payloads(path: str) -> None:
    workflow = deepcopy(_workflow())
    upload = _step(workflow, "Upload sanitized containment mechanics summary")
    upload["with"]["path"] = path
    with pytest.raises(AssertionError):
        _assert_publication_boundary(workflow)
