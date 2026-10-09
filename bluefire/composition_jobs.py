"""Fresh grant-owned attempts using the existing native run and receiver owners."""

from __future__ import annotations

import threading
import time
from datetime import datetime

from . import (
    capability_file_access,
    composition_admission,
    composition_context,
    composition_file_access,
)
from .capability_composition import compile_initial_graph, compile_revision
from .capability_facts import seal_facts, validate_facts
from .capability_grant import objective_result, validate_grant
from .capability_packs import FILE_ACCESS_PACK, grant_pack, review_pack
from .composition_authority import GrantExecution, native_envelope
from .contracts import ExecutionMode, ScenarioDefinition
from .detection_evaluations import _source, _source_binding
from .job_runtime import JobCancelled, JobResult, JobRuntimeError
from .orchestrator import Orchestrator
from .owned_receiver_registry import OwnedReceiverRegistry, handoff_artifact
from .product_store_assistance import job_at, patch
from .product_store_contracts import safe_document
from .product_store_errors import ProductStoreError
from .receiver_defense_jobs import fields
from .receiver_session_contract import validate_terminal
from .runner_contracts import _verified_grant_attempt, _verified_grant_cleanup
from .util import content_hash

OWNER_KIND = "composition.objective"
ATTEMPT_KIND = "composition.attempt"


def now_ms():
    return time.time_ns() // 1_000_000


class CompositionJobs:
    def __init__(self, service, *, factory=None, clock=now_ms):
        self.service = service
        self.store = service.product_store
        self.controller = service.job_controller
        self.clock = clock
        self._authorization_lock = threading.Lock()
        self.owners = OwnedReceiverRegistry(
            state=lambda identifier: self.store.get_job(identifier)["progress"],
            publish=self._publish,
            factory=factory,
        )

    def _publish(self, identifier, values):
        checked = safe_document(values, context="composition progress")
        with self.store._connection(write=True) as connection:
            job = job_at(self.store, connection, identifier)
            if job["kind"] not in {OWNER_KIND, ATTEMPT_KIND}:
                raise ProductStoreError("Composition progress has another job owner.")
            patch(connection, job, checked)

    def _owner(self, identifier):
        owner = self.store.get_job(identifier)
        if owner["kind"] != OWNER_KIND:
            raise ProductStoreError("Select a saved composition objective.")
        return owner

    def review(self, request):
        pack = review_pack(request)
        return composition_context.review(
            self.service,
            request["control_owner_id"],
            question=request["question"],
            limits=request["limits"],
            pack=pack,
        )

    def authorize(self, request):
        with self._authorization_lock:
            return composition_admission.authorize(self, request)

    def _current(self, owner, *, allow_exhausted=False):
        if (
            owner["state"] != "completed"
            or owner["progress"].get("admission") != {"accepted": True, "problem": None}
            or owner["progress"].get("stopped")
        ):
            raise ProductStoreError("The reviewed objective is not admitted for fresh work.")
        for child in self._children(owner["job_id"]):
            result = child["progress"].get("verified_result", {})
            if (
                child["progress"].get("settlement") == "settled"
                and result.get("objective", {}).get("established") is True
            ):
                attempt = self.store.get_capability_attempt(
                    child["request"]["composition_attempt"]["attempt_id"]
                )
                if self._verified_result(attempt)["objective"]["established"]:
                    raise ProductStoreError(
                        "This objective is established; new business work is closed."
                    )
        grant_view = self.store.get_capability_grant(
            owner["request"]["grant_id"], now_ms=self.clock()
        )
        grant = grant_view["document"]
        if (
            grant_view["status"] not in ({"active", "exhausted"} if allow_exhausted else {"active"})
            or grant["grant_digest"] != owner["request"]["grant_digest"]
        ):
            raise ProductStoreError("The capability grant is stopped, expired or changed.")
        current = composition_context.resolve(
            self.service, grant["environment"]["control_owner_id"], pack=grant_pack(grant)
        )
        validate_grant(
            grant,
            expected_digest=owner["request"]["grant_digest"],
            registry=current["registry"],
            implementation_digests=current["implementation_digests"],
            current_environment=current["current_environment"],
            now_ms=self.clock(),
        )
        return grant, current

    def _facts(self, grant, prior_attempt_id=None):
        if grant_pack(grant) == FILE_ACCESS_PACK:
            if prior_attempt_id is not None:
                raise ProductStoreError(
                    "The fixed file-access route is exhausted; review the retained control explicitly."
                )
            return capability_file_access.seal_facts(grant)
        environment = grant["environment"]

        def fact(identity, kind, source, value, observed=None):
            return {
                "fact_id": identity,
                "kind": kind,
                "provenance": "observed",
                "source": source,
                "observed_at_ms": grant["created_at_ms"] if observed is None else observed,
                "valid_until_ms": grant["expires_at_ms"],
                "environment_digest": content_hash(environment),
                "control_digest": environment["control_digest"],
                "attempt_id": None if kind == "retained_policy" else prior_attempt_id,
                "value": value,
            }

        rows = [
            fact(
                "policy",
                "retained_policy",
                {
                    "kind": "control_record",
                    "id": environment["control_owner_id"],
                    "digest": environment["control_digest"],
                },
                {"status": "retained", "policy_digest": environment["policy_digest"]},
            )
        ]
        prior_graph = None
        if prior_attempt_id is not None:
            attempt = self.store.get_capability_attempt(prior_attempt_id)
            prior_job = self.store.get_job(attempt["lease"]["job_id"])
            marker = prior_job["request"].get("composition_attempt", {})
            prior_owner = self._owner(marker.get("parent_job_id"))
            if (
                attempt["lease"]["grant_id"] != grant["grant_id"]
                or attempt["lease"]["grant_digest"] != grant["grant_digest"]
                or prior_job["kind"] != ATTEMPT_KIND
                or marker.get("attempt_id") != prior_attempt_id
                or prior_owner["request"]["grant_id"] != grant["grant_id"]
                or prior_owner["request"]["grant_digest"] != grant["grant_digest"]
            ):
                raise ProductStoreError("Prior evidence belongs to another delegated objective.")
            if attempt["state"] != "settled":
                raise ProductStoreError("Prior owned effects must settle before a revision.")
            result = self._verified_result(attempt)
            source = {
                "kind": "run_evidence",
                "id": result["run_id"],
                "digest": content_hash(result["source_binding"]),
            }
            finalized = result["source_binding"]["finalized_at"]
            observed = int(
                datetime.fromisoformat(finalized.replace("Z", "+00:00")).timestamp() * 1000
            )
            rows += [
                fact("result", "receiver_result", source, result["receiver_result"], observed),
                fact("cleanup", "cleanup", source, result["cleanup"], observed),
            ]
            prior_graph = attempt["compiled"]["semantic_digest"]
        return seal_facts(
            {
                "schema_version": "bluefire.composition-facts.v1",
                "environment_digest": content_hash(environment),
                "control_digest": environment["control_digest"],
                "prior_attempt_id": prior_attempt_id,
                "prior_graph_digest": prior_graph,
                "facts": rows,
            }
        )

    def validate_proposal(self, owner_id, proposal, *, prior_attempt_id=None, _retry_job_id=None):
        owner = self._owner(owner_id)
        if owner["state"] != "completed" or owner["progress"].get("stopped"):
            raise ProductStoreError("The reviewed objective is not admitted for fresh work.")
        grant, current = self._current(owner)
        facts = self._facts(grant, prior_attempt_id)
        compiler = compile_initial_graph if prior_attempt_id is None else compile_revision
        prior_graphs = []
        for job in self._children(owner_id):
            if job["job_id"] == _retry_job_id:
                continue
            try:
                prior = self.store.get_capability_attempt(
                    job["request"]["composition_attempt"]["attempt_id"]
                )
            except ProductStoreError:
                if job["state"] not in {"failed", "cancelled", "interrupted"}:
                    raise ProductStoreError(
                        "The previous attempt admission is not settled."
                    ) from None
            else:
                prior_graphs.append(prior["compiled"]["semantic_digest"])
        if prior_attempt_id is None and prior_graphs:
            raise ProductStoreError(
                "A subsequent graph requires the actual previous attempt evidence."
            )
        return compiler(
            proposal,
            grant=grant,
            expected_grant_digest=owner["request"]["grant_digest"],
            registry=current["registry"],
            implementation_digests=current["implementation_digests"],
            current_environment=current["current_environment"],
            facts=facts,
            expected_facts_digest=facts["facts_digest"],
            now_ms=self.clock(),
            **({"previous_semantic_digests": prior_graphs} if prior_attempt_id is not None else {}),
        )

    def attempt(self, owner_id, request):
        fields(request, {"submission_id", "proposal", "prior_attempt_id"})
        job_id, _ = self.store._job_submission_binding(
            request["submission_id"], content_hash(request)
        )
        identity = job_id[4:]
        try:
            previous = self.store.get_job("job-" + identity)
        except ProductStoreError:
            previous = None
        compiled = self.validate_proposal(
            owner_id,
            request["proposal"],
            prior_attempt_id=request["prior_attempt_id"],
            _retry_job_id="job-" + identity if previous is not None else None,
        )
        if previous is not None:
            marker = previous["request"].get("composition_attempt", {})
            if previous["kind"] != ATTEMPT_KIND or marker.get("parent_job_id") != owner_id:
                raise ProductStoreError("This attempt submission belongs to another operation.")
            submitted = previous["progress"].get("submitted_request")
            if submitted is not None and submitted != request:
                raise ProductStoreError(
                    "This submission already identifies another exact proposal."
                )
            try:
                old = self.store.get_capability_attempt(marker["attempt_id"])
            except ProductStoreError:
                return self.read(owner_id)
            if old["compiled"]["semantic_digest"] != compiled["semantic_digest"]:
                raise ProductStoreError("This submission already reserved a different graph.")
            return self.read(owner_id)
        grant, _ = self._current(self._owner(owner_id))
        marker = {
            "parent_job_id": owner_id,
            "grant_id": grant["grant_id"],
            "grant_digest": grant["grant_digest"],
            "attempt_id": "attempt-" + identity,
            "compiled_digest": compiled["compiled_digest"],
            "run_id": self.service.store._new_run_id(),
        }
        child_request = {"composition_attempt": marker}
        submitted = safe_document(request, context="composition attempt submission")

        def execute(ctx, value):
            self._publish(ctx.job_id, {"submitted_request": submitted})
            return self._execute(ctx, value, compiled)

        child = self.controller.submit(
            ATTEMPT_KIND,
            child_request,
            submission_id=request["submission_id"],
            intent_digest=content_hash(child_request),
            callback=execute,
        )
        self._publish(child["job_id"], {"submitted_request": submitted})
        return self.read(owner_id)

    def _orchestrator(self, current, **kwargs):
        return Orchestrator(
            current["registry"],
            self.service.store,
            runner=current["runner"],
            action_bindings=self.service._catalog_snapshot.action_bindings,
            provider_artifacts=self.service._catalog_snapshot.provider_artifacts,
            catalog_authority=self.service._catalog_snapshot.to_dict(),
            **(
                {"file_access_binding": current["file_access_binding"]}
                if "file_access_binding" in current
                else {}
            ),
            **kwargs,
        )

    def _execute(self, ctx, request, compiled):
        marker = request["composition_attempt"]
        owner = self._owner(marker["parent_job_id"])
        grant, current = self._current(owner)
        scenario = ScenarioDefinition.from_mapping(compiled["scenario"])
        orchestrator = self._orchestrator(current)
        plan = orchestrator.planner.compile(
            scenario,
            mode=ExecutionMode.EXECUTE,
            profile=current["profile"],
            autonomy="off",
            ai_enabled=False,
            action_implementations=compiled["action_implementations"],
        )
        envelope = native_envelope(plan, compiled)
        lease = self.store.reserve_capability_attempt(
            grant["grant_id"],
            compiled,
            expected_compiled_digest=marker["compiled_digest"],
            attempt_id=marker["attempt_id"],
            job_id=ctx.job_id,
            run_id=marker["run_id"],
            plan_digest=content_hash(plan.to_dict()),
            native_envelope_digest=content_hash(envelope),
            current_environment=current["current_environment"],
            now_ms=self.clock(),
        )
        claim = self.store.claim_capability_attempt(
            marker["attempt_id"],
            lease_digest=lease["lease_digest"],
            current_environment=current["current_environment"],
            now_ms=self.clock(),
        )
        return self._run_attempt(
            ctx, marker, compiled, grant, current, scenario, envelope, lease, claim
        )

    def _run_attempt(self, ctx, marker, compiled, grant, current, scenario, envelope, lease, claim):
        attempt_id = marker["attempt_id"]
        file_access = grant_pack(grant) == FILE_ACCESS_PACK
        done = threading.Event()
        started = time.monotonic()
        origin = self.clock()
        registered: set[str] = set()
        no_effect_terminals = {}
        cleanup_result = None
        cleanup_claim = None
        workspace = None

        def check():
            observed = self.clock()
            if (
                ctx.cancellation_event.is_set()
                or not lease["created_at_ms"] <= observed < lease["business_expires_at_ms"]
            ):
                ctx.cancellation_event.set()
                raise JobCancelled("Capability business authority ended; cleanup remains separate.")
            _, fresh = self._current(self._owner(marker["parent_job_id"]), allow_exhausted=True)
            return fresh

        def watch():
            while not done.wait(0.1):
                observed = self.clock()
                try:
                    state = self.store.get_capability_grant(grant["grant_id"], now_ms=observed)[
                        "status"
                    ]
                    monotonic_expired = (
                        origin + (time.monotonic() - started) * 1000
                        >= lease["business_expires_at_ms"]
                    )
                    if (
                        state not in {"active", "exhausted"}
                        or observed < origin
                        or observed >= lease["business_expires_at_ms"]
                        or monotonic_expired
                    ):
                        ctx.cancellation_event.set()
                        return
                except Exception:
                    ctx.cancellation_event.set()
                    return

        def bind_profile(profile):
            fresh = check()
            self.store.bind_capability_workspace(
                attempt_id,
                runner_policy_digest=profile["policy_digest"],
                workspace_path_digest=content_hash({"sandbox_root": profile["sandbox_root"]}),
                now_ms=self.clock(),
                current_environment=fresh["current_environment"],
            )

        def cleanup_authority(profile, params, receipts):
            nonlocal cleanup_claim, cleanup_result
            requested = params["receipt_ids"]
            if len(requested) != len(set(requested)) or set(requested) != set(receipts):
                raise ProductStoreError(
                    "Cleanup must cover every independently discovered owned receipt exactly once."
                )
            tasks = {
                row["request_hash"]: row
                for row in self.store.get_capability_attempt(attempt_id)["tasks"]
            }
            rows = []
            workspace_ids = set()
            if not requested:
                if receipts or set(no_effect_terminals) != {
                    row["task_id"] for row in tasks.values()
                }:
                    raise ProductStoreError(
                        "Empty cleanup does not prove absence of owned effects."
                    )
                proof = {
                    "schema_version": "bluefire.capability-no-effects.v1",
                    "attempt_id": attempt_id,
                    "lease_digest": lease["lease_digest"],
                    "terminals": dict(sorted(no_effect_terminals.items())),
                }
                cleanup_result = {"digest": content_hash(proof), "no_effects": proof}
                return None
            for receipt_id in requested:
                receipt = receipts.get(receipt_id)
                if receipt is None or receipt["request_hash"] not in tasks:
                    raise ProductStoreError(
                        "Cleanup receipt is outside the exact registered attempt."
                    )
                workspace_ids.add(receipt["workspace_id"])
                rows.append(
                    {
                        "receipt_id": receipt_id,
                        "source_request_hash": receipt["request_hash"],
                        "source_task_id": tasks[receipt["request_hash"]]["task_id"],
                    }
                )
            if len(workspace_ids) != 1:
                raise ProductStoreError("Cleanup receipts do not share the owned workspace.")
            self.store.record_capability_cleanup_obligation(
                attempt_id, workspace_id=workspace_ids.pop(), receipts=rows
            )
            observed = self.clock()
            cleanup_claim = self.store.claim_capability_cleanup(
                attempt_id,
                now_ms=observed,
                timeout_ms=min(
                    lease["reservation"]["cleanup_reserve_ms"],
                    lease["attempt_expires_at_ms"] - observed,
                ),
            )
            if cleanup_claim["document"]["runner_policy_digest"] != profile["policy_digest"]:
                raise ProductStoreError("Cleanup changed the sealed runner profile.")
            return _verified_grant_cleanup(
                cleanup_claim["document"], expected_document_digest=cleanup_claim["document_digest"]
            )

        def before_task(step, inputs, manifest, task_id):
            if "grant_cleanup" in manifest:
                if cleanup_claim is None:
                    raise ProductStoreError("The cleanup claim is unavailable.")
                self.store.register_capability_cleanup_task(
                    attempt_id,
                    task_id=task_id,
                    request_hash=manifest["request_hash"],
                    expected_document_digest=cleanup_claim["document_digest"],
                    now_ms=self.clock(),
                )
                registered.add(task_id)
                return
            fresh = check()
            material = (
                None
                if file_access
                else handoff_artifact(
                    step,
                    inputs,
                    manifest,
                    step_id=compiled["handoff"]["step_id"],
                    port=compiled["handoff"]["port"],
                )
            )
            self.store.register_capability_task(
                attempt_id,
                task_id=task_id,
                step_id=step.step_id,
                request_hash=manifest["request_hash"],
                now_ms=self.clock(),
                current_environment=fresh["current_environment"],
            )
            registered.add(task_id)
            try:
                if material is not None:
                    state = self.store.get_job(ctx.job_id)["progress"]
                    if state.get("task_binding") is not None:
                        raise ProductStoreError("The owned receiver handoff was already consumed.")
                    task = {"task_id": task_id, **material}
                    self._publish(ctx.job_id, {"task_binding": task})
                    owner = self.owners.current(ctx.job_id, state["session"])
                    owner.bind_task(
                        task_id,
                        digest=material["sha256"],
                        size=material["size_bytes"],
                        review_digest=state["session"]["review_digest"],
                    )
                check()
            except BaseException:
                after_task(
                    step,
                    manifest,
                    task_id,
                    {
                        "schema_version": "bluefire.task-not-sent.v1",
                        "task_id": task_id,
                        "request_hash": manifest["request_hash"],
                    },
                )
                raise

        def after_task(step, manifest, task_id, result, *, observed_receipt_ids=None):
            nonlocal cleanup_result
            if task_id not in registered:
                return
            terminal = content_hash(result)
            if "grant_cleanup" in manifest:
                self.store.record_capability_cleanup_terminal(
                    task_id, request_hash=manifest["request_hash"], terminal_digest=terminal
                )
                if (
                    result.get("status") == "success"
                    and result.get("cleanup", {}).get("verification_performed") is True
                ):
                    cleanup_result = {"digest": terminal, "report": result["cleanup"]}
            else:
                self.store.record_capability_task_terminal(
                    task_id, request_hash=manifest["request_hash"], terminal_digest=terminal
                )
                if file_access:
                    composition_file_access.record_terminal(
                        self, ctx.job_id, attempt_id, current, step, manifest, task_id, result
                    )
                if result.get("schema_version") == "bluefire.task-not-sent.v1" or (
                    result.get("status") in {"refused", "control_blocked"}
                    and result.get("receipt_ids") == []
                    and observed_receipt_ids == ()
                ):
                    no_effect_terminals[task_id] = terminal

        execution = GrantExecution(
            _verified_grant_attempt(
                claim["document"], expected_document_digest=claim["document_digest"]
            ),
            envelope,
            check,
            bind_profile,
            before_task,
            after_task,
            cleanup_authority,
        )
        monitor = threading.Thread(
            target=watch, name="composition-deadline-" + attempt_id[-8:], daemon=True
        )
        monitor.start()
        run_result = None
        try:
            fresh = check()
            self.store.start_capability_preparation(
                attempt_id, now_ms=self.clock(), current_environment=fresh["current_environment"]
            )
            if file_access:
                composition_file_access.prepare(self, ctx.job_id, attempt_id, fresh)
            else:
                self._publish(ctx.job_id, {"prepare_started": True, "phase": "preparing_receiver"})
                session = self.owners.prepare(
                    ctx.job_id, grant["environment"]["policy_id"], grant["environment"]["port"]
                )
                self._publish(ctx.job_id, {"session": session})
                self.store.bind_capability_receiver(
                    attempt_id,
                    session_generation=session["receiver_session_id"],
                    review_digest=session["review_digest"],
                )
            current = check()
            workspace = self.service._isolated_owned_sandbox(current["sandbox"], attempt_id)
            orchestrator = self._orchestrator(current, grant_execution=execution)
            collector_authority = None
            if current["collector_runtime"] is not None:
                orchestrator.collector_registry, collector_authority = (
                    self.service._managed_collector_registry(
                        workspace, current["collector_runtime"]
                    )
                )
            run_result = orchestrator.run(
                scenario,
                mode=ExecutionMode.EXECUTE,
                profile=current["profile"],
                sandbox_root=workspace,
                target_scope=current["run_intent"]["target_scope"],
                autonomy="off",
                ai_enabled=False,
                action_implementations=compiled["action_implementations"],
                runner_readiness=current["runner_readiness"],
                collector_ids=current["collector_ids"],
                collector_runtime_settings=current["collector_runtime"],
                collector_registry_authority=collector_authority,
                cancel_event=ctx.cancellation_event,
                checkpoint=ctx.checkpoint,
            )
            self.service._index_run(run_result)
            return JobResult(result_ref=marker["run_id"], progress={"phase": "attempt_completed"})
        finally:
            done.set()
            monitor.join(timeout=2)
            if monitor.is_alive():
                ctx.cancellation_event.set()
                raise ProductStoreError("The attempt deadline monitor did not stop.")
            if not file_access:
                state = self.store.get_job(ctx.job_id)["progress"]
                try:
                    observation = self.owners.observe_bound(
                        ctx.job_id, state.get("session"), state.get("task_binding")
                    )
                finally:
                    closed = self.owners.close(ctx.job_id)
                self._publish(
                    ctx.job_id, {"receiver_observation": observation, "receiver_closed": closed}
                )
            self._publish(
                ctx.job_id,
                {
                    "native_cleanup": cleanup_result,
                    "finalized_run_id": marker["run_id"] if run_result is not None else None,
                },
            )
            if cleanup_result is None and registered and registered == set(no_effect_terminals):
                proof = {
                    "schema_version": "bluefire.capability-no-effects.v1",
                    "attempt_id": attempt_id,
                    "lease_digest": lease["lease_digest"],
                    "terminals": dict(sorted(no_effect_terminals.items())),
                }
                cleanup_result = {"digest": content_hash(proof), "no_effects": proof}
                self._publish(ctx.job_id, {"native_cleanup": cleanup_result})
            self._settle_attempt(marker, ctx.job_id, lease, run_result, cleanup_result)

    def _settle_attempt(self, marker, job_id, lease, run_result, cleanup_result):
        state = self.store.get_job(job_id)["progress"]
        if state.get("file_access_dependency") is not None:
            return composition_file_access.settle(
                self, marker, job_id, lease, run_result, cleanup_result
            )
        session = state.get("session")
        if (
            session is None
            or state.get("receiver_closed") is not True
            or not state.get("receiver_cleanup_receipt")
        ):
            self._publish(job_id, {"settlement": "pending_cleanup"})
            return
        attempt = self.store.get_capability_attempt(marker["attempt_id"])
        tasks = attempt["tasks"]
        native = {"state": "not_started", "run_id": marker["run_id"]}
        if tasks:
            cleanup = (run_result or {}).get("cleanup", {})
            if cleanup_result is None and not (
                cleanup.get("success") is True and cleanup.get("outstanding_receipt_count") == 0
            ):
                self._publish(job_id, {"settlement": "pending_cleanup"})
                return
            native = {
                "state": "complete",
                "run_id": marker["run_id"],
                "task_ids": sorted(row["task_id"] for row in tasks),
                "cleanup_digest": (
                    cleanup_result["digest"] if cleanup_result else content_hash(cleanup)
                ),
            }
        receipt = {
            "schema_version": "bluefire.capability-attempt-settlement.v1",
            "attempt_id": marker["attempt_id"],
            "lease_digest": lease["lease_digest"],
            "receiver": {
                "state": "verified_closed",
                "session_generation": session["receiver_session_id"],
                "review_digest": session["review_digest"],
                "receipt_digest": content_hash(state["receiver_cleanup_receipt"]),
            },
            "native": native,
        }
        self.store.settle_capability_attempt(marker["attempt_id"], receipt)
        self._publish(job_id, {"settlement": "settled"})
        if run_result is not None:
            try:
                result = self._verified_result(
                    self.store.get_capability_attempt(marker["attempt_id"])
                )
            except (ProductStoreError, KeyError, ValueError) as exc:
                self._publish(job_id, {"verified_result_problem": str(exc)[:1000]})
                return
            self._publish(
                job_id, {"verified_result": result, "verified_result_digest": content_hash(result)}
            )

    def _verified_result(self, attempt):
        lease, compiled = attempt["lease"], attempt["compiled"]
        state = self.store.get_job(lease["job_id"])["progress"]
        run, records, observed = _source(self.service.detection_lab, lease["run_id"])
        if (
            attempt["state"] != "settled"
            or run["scenario"] != compiled["scenario"]
            or run["mode"] != "execute"
            or run["plan"]["autonomy"] != "off"
            or content_hash(run["plan"]) != lease["plan_digest"]
            or run["policy"].get("grant_attempt")
            != _verified_grant_attempt(
                attempt["claim"]["document"],
                expected_document_digest=attempt["claim"]["document_digest"],
            ).to_dict()
        ):
            raise ProductStoreError(
                "The actual finalized run differs from its grant-owned attempt."
            )
        if "file_access" in compiled:
            return composition_file_access.verified_result(self, attempt, run, records, observed)
        session, task, observation = (
            state["session"],
            state["task_binding"],
            state["receiver_observation"],
        )
        expected_task = {"kind": "bind", "review_digest": session["review_digest"], **task}
        if (
            observation.get("state") != "verified"
            or observation.get("review_binding") != session
            or observation.get("task_binding") != expected_task
        ):
            raise ProductStoreError("The exact authenticated receiver observation is unavailable.")
        terminal = validate_terminal(observation["terminal"], session, expected_task)
        decision = terminal["decision"]
        exit_receipt = observation.get("process_exit", {})
        if (
            decision is None
            or decision["decision"] not in {"accepted", "policy_refused"}
            or exit_receipt.get("returncode") != 0
            or exit_receipt.get("process_id") != session["receiver_process_id"]
            or exit_receipt.get("creation_identity") != session["creation_identity"]
        ):
            raise ProductStoreError("The receiver lacks a bound terminal and clean process exit.")
        steps = {row["step_id"]: row for row in run["steps"]}
        handoff = compiled["handoff"]
        stage, peer = steps[handoff["stage_step_id"]], steps[handoff["step_id"]]
        bundle = stage.get("artifacts", {}).get("bundle", {})
        if (
            peer.get("runner_task_id") != task["task_id"]
            or peer.get("action_id") != "sandbox.peer.handoff.v1"
            or bundle.get("type") != "artifact.sandbox.bundle.v1"
            or bundle.get("format") != "jsonl"
            or bundle.get("sha256") != task["sha256"]
            or bundle.get("size") != task["size_bytes"]
        ):
            raise ProductStoreError(
                "Authenticated receiver bytes do not match the staged native artifact."
            )
        grant = self.store.get_capability_grant(lease["grant_id"], now_ms=self.clock())["document"]
        semantics = decision["semantics"]
        receiver_result = {
            "decision": decision["decision"],
            "policy_digest": decision["policy_digest"],
            **{
                key: semantics[key]
                for key in (
                    "record_count",
                    "redacted_record_count",
                    "retained_record_count",
                    "empty_record_count",
                )
            },
        }
        cleanup = {
            "run": (
                "complete"
                if run.get("cleanup", {}).get("success") is True
                and run["cleanup"].get("outstanding_receipt_count") == 0
                else "incomplete"
            ),
            "receiver": "verified_closed" if state.get("receiver_closed") is True else "uncertain",
        }
        outcome = objective_result(
            grant,
            {
                **receiver_result,
                "receiver_verified": True,
                "data_class": "generated_public_jsonl",
                "run_cleanup": cleanup["run"],
                "receiver_cleanup": cleanup["receiver"],
            },
        )
        return {
            "run_id": lease["run_id"],
            "source_binding": _source_binding(run, records, observed),
            "receiver_result": receiver_result,
            "cleanup": cleanup,
            "objective": outcome,
        }

    def read(self, owner_id):
        owner = self._owner(owner_id)
        grant = None
        if owner["progress"].get("admission") == {"accepted": True, "problem": None}:
            grant = self.store.get_capability_grant(
                owner["request"]["grant_id"], now_ms=self.clock()
            )
        children = self._children(owner_id)
        return {
            "schema_version": "bluefire.composition-objective.v1",
            "owner": owner,
            "grant": grant,
            "attempts": children,
        }

    def objectives(self, control_owner_id):
        rows = []
        for owner in self.store.list_jobs():
            if owner["kind"] != OWNER_KIND:
                continue
            submitted = owner["progress"].get("submitted_request", {})
            if owner["progress"].get("admission", {}).get("accepted") is not True:
                review = submitted.get("review", {})
                if review.get("control_owner_id") == control_owner_id:
                    rows.append(
                        {
                            "owner_id": owner["job_id"],
                            "title": review.get("question", "Delegation not admitted"),
                            "status": "refused" if owner["state"] == "completed" else "pending",
                            "job_state": owner["state"],
                        }
                    )
                continue
            grant = self.store.get_capability_grant(
                owner["request"]["grant_id"], now_ms=self.clock()
            )
            if grant["document"]["environment"]["control_owner_id"] != control_owner_id:
                continue
            rows.append(
                {
                    "owner_id": owner["job_id"],
                    "title": grant["document"]["objective"]["question"],
                    "status": grant["status"],
                    "job_state": owner["state"],
                }
            )
        return {"schema_version": "bluefire.composition-objective-list.v1", "objectives": rows}

    def _children(self, owner_id):
        return [
            job
            for job in self.store.list_jobs()
            if job["kind"] == ATTEMPT_KIND
            and job["request"].get("composition_attempt", {}).get("parent_job_id") == owner_id
        ]

    def proposal_context(self, owner_id, *, prior_attempt_id=None):
        grant, current = self._current(self._owner(owner_id))
        facts = self._facts(grant, prior_attempt_id)
        validate_facts(
            facts,
            expected_digest=facts["facts_digest"],
            grant=grant,
            now_ms=self.clock(),
            require_prior_result=prior_attempt_id is not None,
        )
        initial = None
        initial_scenario = None
        if prior_attempt_id is None:
            if grant_pack(grant) == FILE_ACCESS_PACK:
                initial = capability_file_access.initial_proposal()
                initial_scenario = self.validate_proposal(owner_id, initial)["scenario"]
                return composition_file_access.proposal_context(
                    grant, facts, initial, initial_scenario
                )
            source = current["source_context"]["scenario"]
            scenario = ScenarioDefinition.from_mapping(source)
            plan = self._orchestrator(current).planner.compile(
                scenario,
                mode=ExecutionMode.EXECUTE,
                profile=current["profile"],
                autonomy="off",
                ai_enabled=False,
            )
            method_ids = {row["action_id"] for row in grant["snapshot"]["methods"]}
            if any(step.action_id not in method_ids for step in plan.steps):
                raise ProductStoreError(
                    "The established graph uses a method outside this grant snapshot."
                )
            initial = {
                "schema_version": "bluefire.composition-proposal.v1",
                "title": source["title"],
                "start": source["start"],
                "steps": [
                    {
                        "id": step.step_id,
                        "behavior_id": step.action_id,
                        "parameters": dict(step.parameters),
                    }
                    for step in plan.steps
                ],
                "edges": source["edges"],
                "evidence_refs": ["policy"],
                "rationale": "Exercise the saved material route under the retained receiver policy.",
            }
            initial_scenario = self.validate_proposal(owner_id, initial)["scenario"]
        return {
            "schema_version": "bluefire.composition-proposal-context.v1",
            "grant_id": grant["grant_id"],
            "objective": grant["objective"],
            "snapshot": grant["snapshot"],
            "facts": facts,
            "initial_proposal": initial,
            "initial_scenario": initial_scenario,
        }

    def stop(self, owner_id, *, revoke=False):
        owner = self._owner(owner_id)
        if not isinstance(owner["request"].get("grant_id"), str):
            raise ProductStoreError("No capability grant was issued for this delegation.")
        state = self.store.change_capability_grant_state(
            owner["request"]["grant_id"],
            status="revoked" if revoke else "paused",
            now_ms=self.clock(),
        )
        self._publish(owner_id, {"stopped": True})
        try:
            self.service.composition_ai.stop_owner(owner_id)
        finally:
            for row in state["attempts"]:
                try:
                    self.controller.cancel(row["job_id"])
                except JobRuntimeError:
                    pass
                self.owners.close(row["job_id"])
        return self.read(owner_id)

    def continue_objective(self, owner_id):
        owner = self._owner(owner_id)
        if not isinstance(owner["request"].get("grant_id"), str):
            raise ProductStoreError("No capability grant was issued for this delegation.")
        grant = self.store.get_capability_grant(owner["request"]["grant_id"], now_ms=self.clock())[
            "document"
        ]
        current = composition_context.resolve(
            self.service, grant["environment"]["control_owner_id"], pack=grant_pack(grant)
        )
        self.store.change_capability_grant_state(
            grant["grant_id"],
            status="active",
            now_ms=self.clock(),
            current_environment=current["current_environment"],
        )
        self._publish(owner_id, {"stopped": False})
        return self.read(owner_id)
