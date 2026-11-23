"""Existing Assistant jobs coordinating native receiver work and bounded analysis."""

import uuid

from . import product_store_assistance_receiver as records
from .ai_assistance import RECEIVER_INSPECT, RECEIVER_TEST
from .ai_receiver_inspection import inspect, validate_output
from .ai_wire import AIProviderCancelled, AIProviderError
from .assistance_receiver_context import context, fresh, prefix
from .assistance_results import TERMINAL, child_job
from .job_runtime import JobCancelled, JobResult, JobRuntimeError
from .product_store_assistance import reserve
from .product_store_errors import ProductStoreError
from .receiver_defense_contract import INSPECT_KIND
from .util import content_hash


class ReceiverAssistance:
    def __init__(self, service):
        self.service = service
        self.store = service.product_store
        self.controller = service.job_controller

    def context(self, selected):
        return context(self.service, selected)

    def fresh(self, parent):
        return fresh(self.service, parent)

    def _owner(self, parent, step):
        selected = parent["request"]["context"]["selected"]
        if selected["kind"] == "receiver_test":
            return selected["receiver_job_id"], False
        child = child_job(self.service, parent, step)
        return (child["job_id"] if child else None), True

    def advance(self, parent, *, recovery=False):
        plan = parent["progress"].get("plan", [])
        if not plan:
            return
        selected = parent["request"]["context"]["selected"]
        creating = selected["kind"] == "receiver_scenario"
        expected = RECEIVER_TEST if creating else RECEIVER_INSPECT
        if (
            len(plan) != 1
            or plan[0]["capability_id"] != expected
            or plan[0]["detector_ref"] != "none"
        ):
            raise ProductStoreError("Receiver assistance requires its exact single capability.")
        step = plan[0]
        owner_id, _ = self._owner(parent, step)
        if owner_id is None:
            identifier = str(
                uuid.uuid5(
                    uuid.UUID(parent["request"]["submitted_request"]["submission_id"]),
                    "capability:" + step["step_id"],
                )
            )
            native = parent["request"]["context"]["receiver_context"]
            request = {
                "submission_id": identifier,
                "selection": selected["selection"],
                "run_intent": selected["run_intent"],
                "context_digest": native["context_digest"],
            }
            reservation = {
                "job_id": "job-" + uuid.UUID(identifier).hex,
                "submission_id": identifier,
                "kind": "receiver.defense",
                "object_id": native["context_digest"],
                "request": request,
            }
            reserve(self.store, parent["job_id"], step["step_id"], reservation)
            self.service.receiver_defense.submit(
                request,
                _assistance_turn={"parent_job_id": parent["job_id"], "step_id": step["step_id"]},
            )
            return
        view, phases = prefix(self.service, owner_id)
        if not creating:
            phases = parent["request"]["context"]["source_prefix"]
        if not phases:
            return
        offered = self._offer(view, phases)
        request = {
            "owner_job_id": owner_id,
            "phases": phases,
            "offered_next_phase": offered,
            "prefix_digest": content_hash(phases),
        }
        reserved = records.reserve(self.store, parent["job_id"], request, recovery=recovery)
        request = reserved["request"]
        document = {
            "submitted_request": request,
            "context_digest": request["prefix_digest"],
            "assistance_receiver": {"parent_job_id": parent["job_id"], "owner_job_id": owner_id},
        }
        if not creating and not parent["progress"].get("children", {}).get(step["step_id"]):
            reserve(
                self.store,
                parent["job_id"],
                step["step_id"],
                {
                    **{key: reserved[key] for key in ("job_id", "submission_id")},
                    "kind": INSPECT_KIND,
                    "object_id": request["prefix_digest"],
                    "request": request,
                },
            )
            document["assistance_turn"] = {
                "parent_job_id": parent["job_id"],
                "step_id": step["step_id"],
            }
        elif (
            not creating
            and parent["progress"]["children"][step["step_id"]]["job_id"] == reserved["job_id"]
        ):
            document["assistance_turn"] = {
                "parent_job_id": parent["job_id"],
                "step_id": step["step_id"],
            }
        previous = self.store.get_job_submission(
            INSPECT_KIND,
            submission_id=reserved["submission_id"],
            intent_digest=content_hash(request),
        )
        if previous is None:
            self.controller.submit(
                INSPECT_KIND,
                document,
                callback=self._inspect,
                submission_id=reserved["submission_id"],
                intent_digest=content_hash(request),
            )

    @staticmethod
    def _offer(view, phases):
        wanted = "protected" if len(phases) == 1 else "restored" if len(phases) == 2 else None
        phase = next((row for row in view["phases"] if row["phase"] == wanted), None)
        return wanted if phase and phase["prepare_allowed"] else None

    def _verify_request(self, job):
        request = job["request"]["submitted_request"]
        marker = job["request"]["assistance_receiver"]
        parent = self.service.assistance._job(marker["parent_job_id"])
        self.fresh(parent)
        if content_hash(request["phases"]) != request["prefix_digest"]:
            raise ProductStoreError("Receiver analysis prefix is invalid.")
        _, current = prefix(self.service, marker["owner_job_id"])
        if current[: len(request["phases"])] != request["phases"]:
            raise ProductStoreError("Receiver analysis source facts changed.")
        return parent, request

    def _inspect(self, ctx, document):
        try:
            job = self.store.get_job(ctx.job_id)
            with self.service._runtime_configuration_lock:
                with self.store._connection() as connection:
                    records.publication_guard(self.store, connection, INSPECT_KIND, job["request"])
                parent, request = self._verify_request(job)
                provider = self.service.assistance._provider(parent)
            ctx.checkpoint()
            interpretation = inspect(
                config=provider,
                access=self.service._provider_access,
                cancel=ctx.cancellation_event,
                phases=request["phases"],
                offered_next_phase=request["offered_next_phase"],
            )
            ctx.checkpoint()
            with self.service._runtime_configuration_lock:
                self._verify_request(job)
                self.service.assistance._provider(parent)
                records.retain(self.store, ctx.job_id, interpretation)
            return JobResult(progress={"analysis_complete": True})
        except AIProviderCancelled as exc:
            raise JobCancelled("Receiver analysis cancellation confirmed.") from exc

    def _inspection_jobs(self, parent):
        jobs = []
        for reserved in parent["progress"].get("receiver_inspections", []):
            try:
                job = self.store.get_job(reserved["job_id"])
            except ProductStoreError:
                continue
            request = job["request"]["submitted_request"]
            if (
                job["kind"] != INSPECT_KIND
                or request != reserved["request"]
                or job["request"]["assistance_receiver"]
                != {"parent_job_id": parent["job_id"], "owner_job_id": request["owner_job_id"]}
                or job["request"]["_submission"]["intent_digest"] != content_hash(request)
                or job["job_id"] != "job-" + uuid.UUID(reserved["submission_id"]).hex
                or job["request"]["_submission"]["submission_id"] != reserved["submission_id"]
                or request["submission_id"] != reserved["submission_id"]
            ):
                raise ProductStoreError("Receiver inspection receipt lineage is invalid.")
            jobs.append(job)
        return jobs

    def inspections(self, parent, *, verified_sources=None):
        outputs = []
        sources = dict(verified_sources or {})
        for job in self._inspection_jobs(parent):
            request = job["request"]["submitted_request"]
            interpretation = job["progress"].get("interpretation")
            owner_id = request["owner_job_id"]
            if owner_id not in sources:
                _, sources[owner_id] = prefix(self.service, owner_id)
            source = sources[owner_id]
            if (
                content_hash(request["phases"]) != request["prefix_digest"]
                or source[: len(request["phases"])] != request["phases"]
            ):
                raise ProductStoreError(
                    "Receiver inspection has a different verified source prefix."
                )
            if interpretation is not None:
                if (
                    interpretation.get("schema_version")
                    != "bluefire.receiver-defense-inspection.v1"
                    or interpretation.get("model_interpretation") is not True
                    or job["progress"].get("interpretation_digest") != content_hash(interpretation)
                    or interpretation["context_digest"]
                    != content_hash(
                        {
                            "phases": request["phases"],
                            "offered_next_phase": request["offered_next_phase"],
                        }
                    )
                    or any(
                        interpretation["provider"][key] != parent["progress"]["provider"][key]
                        for key in ("provider_id", "kind", "model")
                    )
                ):
                    raise ProductStoreError("Receiver interpretation digest is invalid.")
                try:
                    validate_output(
                        {
                            key: interpretation[key]
                            for key in (
                                "summary",
                                "findings",
                                "limitations",
                                "next_phase",
                                "reason",
                            )
                        },
                        evidence_refs=[row["evidence_ref"] for row in request["phases"]],
                        offered_next_phase=request["offered_next_phase"],
                    )
                except AIProviderError as exc:
                    raise ProductStoreError("Retained receiver interpretation is invalid.") from exc
            outputs.append(
                {
                    "job": self.service.job(job["job_id"]),
                    "owner_job_id": request["owner_job_id"],
                    "prefix_digest": request["prefix_digest"],
                    "phases": request["phases"],
                    "interpretation": interpretation,
                }
            )
        return outputs

    def apply_view(self, parent, step, view):
        owner_id, owns = self._owner(parent, step)
        if owner_id is None:
            return False
        native, phases = prefix(self.service, owner_id)
        inspections = self.inspections(parent, verified_sources={owner_id: phases})
        bound = phases if owns else parent["request"]["context"]["source_prefix"]
        latest = (
            next(
                (
                    row
                    for row in reversed(inspections)
                    if row["prefix_digest"] == content_hash(bound)
                ),
                None,
            )
            if bound
            else None
        )
        path = "/compare?receiver_job=" + owner_id
        view["receiver_test"] = {
            "owner_job_id": owner_id,
            "owner_context_digest": native["job"]["request"]["context_digest"],
            "owns_lifecycle": owns,
            "status": native["status"],
            "native_path": path,
            "phase": native["next_action"]["phase"],
            "next_action": native["next_action"],
            "phases": native["phases"],
            "inspections": inspections,
        }
        for row, phase in zip(bound, native["phases"], strict=False):
            view["results"].append(
                {
                    "kind": "receiver_phase",
                    "step_id": step["step_id"],
                    "owner_job_id": owner_id,
                    "phase": row["phase"],
                    "run_id": phase["result"]["run_id"],
                    "result_digest": row["result_digest"],
                    "decision": row["decision"],
                    "native_path": path,
                }
            )
        for item in inspections:
            if item["interpretation"]:
                view["results"].append(
                    {
                        "kind": "receiver_inspection",
                        "step_id": step["step_id"],
                        "owner_job_id": owner_id,
                        "inspection_job_id": item["job"]["job_id"],
                        "prefix_digest": item["prefix_digest"],
                        "native_path": path,
                    }
                )
        current = next(
            (row for row in native["phases"] if row["phase"] == native["next_action"]["phase"]),
            None,
        )
        target = latest["job"] if latest else native["job"]
        if owns and (latest is None or latest["job"]["state"] in TERMINAL) and current:
            for key in ("receiver_job", "execution_job"):
                if current[key] and current[key]["state"] not in TERMINAL:
                    target = current[key]
        view["active_child"] = {
            "job_id": target["job_id"],
            "kind": target["kind"],
            "state": target["state"],
            "step_id": step["step_id"],
            "native_path": path,
        }
        settled = (
            parent["state"] in TERMINAL
            and all(item["job"]["state"] in TERMINAL for item in inspections)
            and (not view.get("continuation") or view["continuation"]["state"] in TERMINAL)
        )
        if (
            latest
            and latest["interpretation"]
            and latest["job"]["state"] in TERMINAL
            and (not owns or native["status"] == "completed")
        ):
            if settled:
                view.update(
                    status="completed",
                    active_child=None,
                    next_action=None,
                )
            else:
                view.update(status="working", next_action=None)
        elif latest and latest["job"]["state"] not in TERMINAL:
            view.update(status="working", next_action=None)
        elif bound and (latest is None or not latest["interpretation"]):
            view.update(
                status="ready_to_continue",
                message="Receiver evidence is retained. Recover the bounded analysis without repeating any receiver or run.",
                next_action={"kind": "continue", "label": "Recover analysis", "native_path": path},
            )
        elif owns and native["status"] in {"blocked", "stopped", "stopping"}:
            view.update(
                status="blocked",
                message="Inspect the native receiver result and cleanup before continuing.",
                next_action={
                    "kind": "review_receiver",
                    "label": "Review receiver test",
                    "native_path": path,
                },
            )
            view["can_start_new_turn"] = native["can_start_new_test"]
        elif owns and (
            native["job"]["state"] not in TERMINAL
            or current
            and current["status"] in {"preparing", "running"}
        ):
            view.update(status="working", next_action=None)
        elif native["next_action"]["kind"] == "approve_execute":
            view.update(
                status="awaiting_execute_approval",
                next_action={
                    "kind": "review_execute",
                    "label": "Review Execute approval",
                    "native_path": native["next_action"]["native_path"],
                },
            )
        else:
            view.update(
                status="awaiting_review",
                next_action={
                    "kind": "review_receiver",
                    "label": "Review receiver test",
                    "native_path": path,
                },
            )
        if (
            view["status"] == "ready_to_continue"
            and view.get("continuation")
            and view["continuation"]["state"] not in TERMINAL
        ):
            view.update(status="working", next_action=None)
        return True

    def settled(self, parent):
        if any(job["state"] not in TERMINAL for job in self._inspection_jobs(parent)):
            return False
        plan = parent["progress"].get("plan", [])
        if not plan:
            return True
        owner_id, owns = self._owner(parent, plan[0])
        if not owns or owner_id is None:
            return True
        native = self.service.receiver_defense.read(owner_id)
        return native["job"]["state"] in TERMINAL and native["can_start_new_test"]

    def cancel(self, parent):
        plan = parent["progress"].get("plan", [])
        if plan:
            owner_id, owns = self._owner(parent, plan[0])
            if owner_id and owns:
                self.service.receiver_defense.cancel(owner_id)
                if self.store.get_job(owner_id)["state"] not in TERMINAL:
                    try:
                        self.controller.cancel(owner_id)
                    except JobRuntimeError:
                        pass
        for job in self._inspection_jobs(parent):
            if job["state"] not in TERMINAL:
                try:
                    self.controller.cancel(job["job_id"])
                except JobRuntimeError:
                    pass

    def cancellation_parent(self, child):
        """Validate both sides before reverse dispatch can durably stop a parent."""
        key = "assistance_receiver" if child["kind"] == INSPECT_KIND else "assistance_turn"
        marker = child["request"].get(key)
        expected_keys = (
            {"parent_job_id", "owner_job_id"}
            if key == "assistance_receiver"
            else {"parent_job_id", "step_id"}
        )
        if not isinstance(marker, dict) or set(marker) != expected_keys:
            raise ProductStoreError("Receiver Assistant cancellation lineage is invalid.")
        parent = self.service.assistance._job(marker["parent_job_id"])
        if child["kind"] == INSPECT_KIND:
            if not any(job["job_id"] == child["job_id"] for job in self._inspection_jobs(parent)):
                raise ProductStoreError("Receiver inspection was not reserved by this turn.")
        else:
            reserved = parent["progress"].get("children", {}).get(marker["step_id"])
            submitted = child["request"].get("submitted_request")
            if (
                child["kind"] != "receiver.defense"
                or not reserved
                or reserved["kind"] != child["kind"]
                or reserved["job_id"] != child["job_id"]
                or reserved["request"] != submitted
                or submitted["submission_id"] != reserved["submission_id"]
                or child["job_id"] != "job-" + uuid.UUID(reserved["submission_id"]).hex
                or child["request"]["_submission"]
                != {
                    "schema_version": "bluefire.job-submission.v1",
                    "submission_id": reserved["submission_id"],
                    "intent_digest": content_hash(submitted),
                }
            ):
                raise ProductStoreError("Receiver owner was not reserved by this exact turn.")
        return parent["job_id"]

    def phase_committed(self, owner_id):
        owner = self.service.receiver_defense._job(owner_id)
        marker = owner["request"].get("assistance_turn")
        if marker:
            # Existing generic hook retains safe recovery guidance on a refused handoff.
            self.service.assistance.application_committed(owner)
