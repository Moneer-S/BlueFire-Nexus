"""Typed boundaries shared by the HTTP shell and its route parser.

The service Protocol is independent of concrete orchestration or HTTP handlers.
"""

from __future__ import annotations

from typing import Any, Mapping, Protocol, Sequence, runtime_checkable

API_PREFIX = "/api/v1"
JsonObject = Mapping[str, Any]
JsonResult = Mapping[str, Any] | Sequence[Any]


@runtime_checkable
class PlatformService(Protocol):
    """Application boundary consumed by both the API shell and other clients.

    Every return value must be JSON serializable.  Request mappings are already
    syntactically valid JSON objects, but domain validation belongs to the
    service so browser, CLI, and future adapters share identical semantics.
    """

    def catalog(self) -> JsonResult:
        """Return the neutral behavior catalog and runner-profile metadata."""

    def scenarios(self) -> JsonResult:
        """Return saved/versioned scenario summaries or documents."""

    def draft_ai_graph(self, request: JsonObject) -> JsonResult:
        """Return one strict, normalized, deliberately unsaved graph draft."""

    def check_ai_provider(self, request: JsonObject) -> JsonResult:
        """Check explicit provider readiness or request one bounded live probe."""

    def settings(self) -> JsonResult:
        """List secret-safe local product settings."""

    def upsert_setting(self, key: str, request: JsonObject) -> JsonResult:
        """Create or replace one local product setting."""

    def scenario_versions(self) -> JsonResult:
        """List active saved scenario versions."""

    def save_scenario_version(self, request: JsonObject) -> JsonResult:
        """Validate and save one content-addressed scenario version."""

    def scenario_version(self, scenario_id: str, *, version: int | None = None) -> JsonResult:
        """Get an active or exact saved scenario version."""

    def resources(self, kind: str) -> JsonResult:
        """List one allowlisted product resource kind."""

    def resource(self, kind: str, resource_id: str) -> JsonResult:
        """Get one allowlisted product resource."""

    def intake_reviewed_t1082(self, request: JsonObject) -> JsonResult:
        """Import the shipped, reviewed T1082 metadata into product-controlled state."""

    def save_resource(
        self,
        kind: str,
        resource_id: str,
        request: JsonObject,
    ) -> JsonResult:
        """Create or replace one secret-safe product resource."""

    def action_packages(self) -> JsonResult:
        """Return the audited signed action-package inventory."""

    def action_package(self, package_id: str) -> JsonResult:
        """Return one signed action package and its immutable history."""

    def install_action_package(self, request: JsonObject) -> JsonResult:
        """Verify and install one signed action-package version."""

    def activate_action_package(
        self,
        package_id: str,
        version: str,
        request: JsonObject,
    ) -> JsonResult:
        """Activate one exact package version against the managed runner."""

    def deactivate_action_package(
        self,
        package_id: str,
        version: str,
        request: JsonObject,
    ) -> JsonResult:
        """Deactivate one exact active package version."""

    def remove_action_package(
        self,
        package_id: str,
        version: str,
        request: JsonObject,
    ) -> JsonResult:
        """Remove one exact inactive package version while retaining audit bytes."""

    def trust_action_package_publisher(self, request: JsonObject) -> JsonResult:
        """Enroll one exact publisher signing key in local trust."""

    def transition_action_package_publisher(
        self,
        publisher_id: str,
        key_id: str,
        action: str,
        request: JsonObject,
    ) -> JsonResult:
        """Suspend or revoke one exact publisher signing key."""

    def detection_health(self) -> JsonResult:
        """Return Detection Lab persistence and backend readiness."""

    def detection_candidates(self) -> JsonResult:
        """List strict persisted detection candidates."""

    def detection_candidate(self, candidate_id: str) -> JsonResult:
        """Return one strict persisted detection candidate."""

    def upsert_detection_hypothesis(self, request: JsonObject) -> JsonResult:
        """Create one immutable candidate definition or return its exact duplicate."""

    def detection_hypothesis_from_run(self, request: JsonObject) -> JsonResult:
        """Import only a verified run candidate's definition into the registry."""

    def evaluate_detection_run(self, candidate_id: str, request: JsonObject) -> JsonResult:
        """Retain an immutable query result against a full observed run bundle."""

    def detection_run_evaluations(self, candidate_id: str) -> JsonResult:
        """Read integrity-checked immutable per-run detector results."""

    def clone_detection_candidate(self, candidate_id: str, request: JsonObject) -> JsonResult:
        """Clone one candidate into a new hypothesis revision."""

    def tune_detection_candidate(self, candidate_id: str, request: JsonObject) -> JsonResult:
        """Tune one candidate into a new hypothesis revision."""

    def submit_detection_ai_revision(self, candidate_id: str, request: JsonObject) -> JsonResult:
        """Submit a durable, explicitly reviewed detection source suggestion."""

    def method_comparison_context(self, run_id: str) -> JsonResult:
        """Read compatible methods in the recorded authority."""

    def assistance_context(self, run_id: str, candidate_id: str) -> JsonResult:
        """Read authoritative saved-object capability context."""

    def assistance_graph_context(self, base_scenario: JsonObject | None = None) -> JsonResult:
        """Read an immutable optional graph reference and capability catalog."""

    def assistance_run_context(self, request: JsonObject) -> JsonResult:
        """Read immutable accepted-graph and native-intent context."""

    def assistance_run_job(self, job_id: str) -> JsonResult:
        """Read native run preparation and linked immutable results."""

    def review_assistance_run(self, job_id: str, request: JsonObject) -> JsonResult:
        """Accept or reject the exact retained native preparation."""

    def graph_ai_job(self, job_id: str) -> JsonResult:
        """Read a retained graph proposal and exact native save receipt."""

    def validate_graph_ai(self, job_id: str, request: JsonObject) -> JsonResult:
        """Validate the frozen native edit and return its canonical server digest."""

    def review_graph_ai(self, job_id: str, request: JsonObject) -> JsonResult:
        """Explicitly accept or reject one durable graph proposal."""

    def submit_assistance_turn(self, request: JsonObject) -> JsonResult:
        """Submit one idempotent contextual assistance turn."""

    def assistance_turn(self, job_id: str) -> JsonResult:
        """Read a contextual turn and its actual native child receipts."""

    def continue_assistance_turn(self, job_id: str, request: JsonObject) -> JsonResult:
        """Recover a retained handoff without repeating completed operations."""

    def submit_method_comparison(self, run_id: str, request: JsonObject) -> JsonResult:
        """Propose one connected method replay and detector comparison."""

    def decide_method_comparison(self, job_id: str, request: JsonObject) -> JsonResult:
        """Review a method proposal and recover its exact replay identity."""

    def decide_detection_ai_revision(self, job_id: str, request: JsonObject) -> JsonResult:
        """Retain one decision and recover its idempotent application job."""

    def revise_detection_source(self, candidate_id: str, request: JsonObject) -> JsonResult:
        """Validate and atomically publish a parsed source revision."""

    def compare_detection_candidates(self, candidate_id: str, request: JsonObject) -> JsonResult:
        """Compare two candidates from the same revision lineage."""

    def parse_detection_candidate(self, candidate_id: str, request: JsonObject) -> JsonResult:
        """Parse or compile one detection candidate."""

    def exercise_detection_fixtures(self, candidate_id: str, request: JsonObject) -> JsonResult:
        """Exercise one parsed candidate against malicious fixtures."""

    def exercise_detection_observed(self, candidate_id: str, request: JsonObject) -> JsonResult:
        """Exercise one candidate against immutable observed run evidence."""

    def evaluate_detection_benign(self, candidate_id: str, request: JsonObject) -> JsonResult:
        """Evaluate one exercised candidate against benign fixtures."""

    def reject_detection_candidate(self, candidate_id: str, request: JsonObject) -> JsonResult:
        """Reject one non-terminal candidate."""

    def activate_resource(
        self,
        kind: str,
        resource_id: str,
        request: JsonObject,
    ) -> JsonResult:
        """Validate and activate one persisted runtime resource."""

    def deactivate_resource(
        self,
        kind: str,
        resource_id: str,
        request: JsonObject,
    ) -> JsonResult:
        """Deactivate one persisted runtime resource."""

    def probe_runner_profile(self, resource_id: str, request: JsonObject) -> JsonResult:
        """Return a sanitized bounded inventory probe for one stored runner profile."""

    def runner_status(self, *, profile_id: str | None = None) -> JsonResult:
        """Return path-free managed-runner lifecycle status."""

    def bootstrap_runner(
        self,
        *,
        profile_id: str | None = None,
        allow_upgrade: bool = False,
    ) -> JsonResult:
        """Explicitly install, verify, and enroll the packaged runner."""

    def start_runner(self, *, profile_id: str | None = None) -> JsonResult:
        """Explicitly start the authenticated runner host."""

    def stop_runner(self, *, profile_id: str | None = None) -> JsonResult:
        """Request authenticated runner shutdown."""

    def revoke_runner(self) -> JsonResult:
        """Revoke trust for a stopped runner."""

    def remove_runner(self, *, confirm_runner_id: str) -> JsonResult:
        """Remove revoked trust after exact identity confirmation."""

    def validate(self, request: JsonObject) -> JsonResult:
        """Validate a scenario graph without executing it."""

    def preflight(self, request: JsonObject) -> JsonResult:
        """Resolve capability, policy, approval, and cleanup readiness."""

    def run(self, request: JsonObject) -> JsonResult:
        """Create a Simulate or Execute run after service-side preflight."""

    def submit_run(self, request: JsonObject) -> JsonResult:
        """Create a durable background run job."""

    def active_jobs(self) -> JsonResult:
        """Return the bounded controller-owned nonterminal job inventory."""

    def job(self, job_id: str) -> JsonResult:
        """Return one durable job snapshot."""

    def retry_job(self, job_id: str) -> JsonResult:
        """Create a safe replacement for one interrupted scenario-run job."""

    def approve_job(self, job_id: str, request: JsonObject) -> JsonResult:
        """Approve one exact Execute job intent."""

    def proposal_reviews(self, job_id: str) -> JsonResult:
        """List durable AI proposal reviews for one job."""

    def proposal_review(self, job_id: str, proposal_record_id: str) -> JsonResult:
        """Return one exact AI proposal review envelope."""

    def accept_proposal_review(
        self,
        job_id: str,
        proposal_record_id: str,
        request: JsonObject,
    ) -> JsonResult:
        """Accept a registered proposal for deterministic continuation."""

    def reject_proposal_review(
        self,
        job_id: str,
        proposal_record_id: str,
        request: JsonObject,
    ) -> JsonResult:
        """Reject a registered proposal without graph mutation."""

    def pause_job(self, job_id: str) -> JsonResult:
        """Request cooperative pause."""

    def resume_job(self, job_id: str) -> JsonResult:
        """Resume a cooperatively paused job."""

    def cancel_job(self, job_id: str) -> JsonResult:
        """Request cooperative cancellation."""

    def list(self) -> JsonResult:
        """Return run summaries suitable for history and comparison."""

    def run_bundle(self, run_id: str) -> bytes: ...

    def detail(self, run_id: str) -> JsonResult:
        """Return one run, including current node and evidence state."""

    def events(self, run_id: str, *, after_sequence: int, limit: int) -> JsonResult:
        """Return one validated page from the tamper-evident run event stream."""

    def prepare_replay(self, run_id: str, request: JsonObject) -> JsonResult: ...

    def submit_replay(self, run_id: str, request: JsonObject) -> JsonResult: ...

    def resolve_replay_submission(self, run_id: str, request: JsonObject) -> JsonResult: ...

    def replay(self, run_id: str, request: JsonObject) -> JsonResult:
        """Create a lineage-linked replay from an immutable prior run."""

    def compare(self, request: JsonObject) -> JsonResult:
        """Compare two or more runs from canonical records."""


class RouteRequest(Protocol):
    """Only the request path and error response are needed to parse routes."""

    path: str

    def _error(self, status: int, code: str, message: str) -> None: ...
