"""Verify retained receiver evidence against its exact ordinary finalized run."""

from . import product_store_receiver_defense as records
from .detection_evaluations import _source, _source_binding
from .product_store_errors import ProductStoreError
from .receiver_policy import ReceiverContentPolicy
from .receiver_session_contract import validate_terminal
from .util import content_hash


def verified_result(coordinator, child):
    result = child["progress"].get("result")
    if result is None:
        return None
    prepared = records.preparation(child)
    marker = child["request"]["receiver_defense"]
    decision = child["progress"].get("decision", {})
    if (
        prepared is None
        or child["progress"].get("result_digest") != content_hash(result)
        or decision.get("decision") != "accept"
        or decision.get("preparation_digest") != prepared["preparation_digest"]
        or result["phase"] != marker["phase"]
        or result["preparation_job_id"] != child["job_id"]
        or result["execution_job_id"] != child["progress"].get("execution_job_id")
        or result["execution_kind"] != prepared["execution_kind"]
    ):
        raise ProductStoreError("The retained receiver result has another native review binding.")
    execution = coordinator.store.get_job(result["execution_job_id"])
    if (
        execution["kind"] != result["execution_kind"]
        or execution["request"].get("receiver_defense") != marker
        or execution["result_ref"] not in {None, result["run_id"]}
    ):
        raise ProductStoreError("The receiver result has another ordinary execution job.")
    run, evidence, observed = _source(coordinator.service.detection_lab, result["run_id"])
    scenario = (
        prepared["run_request"]["scenario"]
        if prepared["execution_kind"] == "scenario.run"
        else prepared["replay_preparation"]["scenario"]
    )
    if (
        "run" in result
        or result["source_binding"] != _source_binding(run, evidence, observed)
        or run["scenario"] != scenario
        or run["mode"] != "execute"
        or run["plan"]["autonomy"] != "off"
    ):
        raise ProductStoreError("The receiver result differs from its finalized native source.")
    session = prepared["session"]
    policy = ReceiverContentPolicy(session["policy"]["policy_id"])
    if (
        result["policy_id"] != policy.policy_id
        or session["policy"] != policy.to_dict()
        or session["policy_digest"] != policy.digest
        or session["review_digest"]
        != content_hash({key: item for key, item in session.items() if key != "review_digest"})
    ):
        raise ProductStoreError("The receiver result differs from its reviewed fixed policy.")
    observation = result["receiver_observation"]
    if observation.get("state") == "verified":
        task = {
            "kind": "bind",
            "review_digest": session["review_digest"],
            **child["progress"]["task_binding"],
        }
        if observation.get("review_binding") != session or observation.get("task_binding") != task:
            raise ProductStoreError("The receiver result has another exact session or task.")
        terminal = validate_terminal(observation["terminal"], session, task)
        content_decision = terminal["decision"]
        established = content_decision is not None and content_decision["decision"] in {
            "accepted",
            "policy_refused",
        }
        expected_decision = content_decision["decision"] if established else "insufficient_evidence"
        expected_artifact = (
            {"sha256": task["sha256"], "size_bytes": task["size_bytes"]} if established else None
        )
        if result["decision"] != expected_decision or result["artifact"] != expected_artifact:
            raise ProductStoreError("The receiver summary differs from its authenticated terminal.")
        exit_receipt = observation["process_exit"]
        if (
            exit_receipt.get("returncode") != 0
            or exit_receipt.get("process_id") != session["receiver_process_id"]
            or exit_receipt.get("creation_identity") != session["creation_identity"]
        ):
            raise ProductStoreError("The receiver result lacks its exact clean process exit.")
        parent = coordinator._job(marker["parent_job_id"])
        handoff = parent["request"]["context"]["handoff"]
        stages = [row for row in run["steps"] if row["step_id"] == handoff["stage_step_id"]]
        peers = [row for row in run["steps"] if row["step_id"] == handoff["handoff_step_id"]]
        if (
            len(stages) != 1
            or len(peers) != 1
            or peers[0].get("runner_task_id") != task["task_id"]
            or peers[0].get("action_id") != "sandbox.peer.handoff.v1"
        ):
            raise ProductStoreError("The authenticated task is absent from the finalized handoff.")
        artifact = stages[0].get("artifacts", {}).get("bundle", {})
        if (
            artifact.get("type") != "artifact.sandbox.bundle.v1"
            or artifact.get("format") != "jsonl"
            or artifact.get("sha256") != task["sha256"]
            or artifact.get("size") != task["size_bytes"]
        ):
            raise ProductStoreError(
                "The authenticated bytes differ from the actual staged artifact."
            )
        if (
            prepared["baseline_artifact"] is not None
            and {"sha256": task["sha256"], "size_bytes": task["size_bytes"]}
            != prepared["baseline_artifact"]
        ):
            raise ProductStoreError(
                "The receiver replay bytes differ from the authenticated baseline."
            )
    elif result["decision"] != "insufficient_evidence" or result["artifact"] is not None:
        raise ProductStoreError(
            "Unavailable receiver evidence cannot establish a content decision."
        )
    cleanup = run.get("cleanup", {})
    expected_run_cleanup = (
        "complete"
        if cleanup.get("success") is True and cleanup.get("outstanding_receipt_count") == 0
        else "incomplete"
    )
    expected_receiver_cleanup = (
        "verified_closed" if child["progress"].get("receiver_closed") is True else "uncertain"
    )
    cleanup_at_finalization = result["cleanup"]
    if (
        cleanup_at_finalization["receiver"] == "uncertain"
        and expected_receiver_cleanup == "verified_closed"
    ):
        expected_receipt = {
            "schema_version": "bluefire.receiver-cleanup.v1",
            "receiver_job_id": child["job_id"],
            "review_digest": session["review_digest"],
            "process_id": session["receiver_process_id"],
            "creation_identity": session["creation_identity"],
            "verified_closed": True,
        }
        if child["progress"].get("receiver_cleanup_receipt") != expected_receipt:
            raise ProductStoreError("Later receiver cleanup lacks its exact owned receipt.")
    elif cleanup_at_finalization["receiver"] != expected_receiver_cleanup:
        raise ProductStoreError("The receiver result changes its recorded cleanup state.")
    if cleanup_at_finalization["run"] != expected_run_cleanup:
        raise ProductStoreError("The receiver result changes its finalized run cleanup.")
    # The finalized bundle already owns the run document. Hydrate the public
    # view only after verification; do not copy transport metadata into jobs.
    return {
        **result,
        "run": run,
        "cleanup_at_finalization": cleanup_at_finalization,
        "cleanup": {"receiver": expected_receiver_cleanup, "run": expected_run_cleanup},
    }
