"""Structural operator-review checks against the current component owners."""

from __future__ import annotations

import re
from pathlib import Path


def operator_source_review_is_human_first(repository: Path) -> bool:
    """Keep exact review, authority controls and raw source in their intended order."""
    frontend = repository / "frontend" / "src"
    try:
        builder = (frontend / "pages" / "Builder.tsx").read_text(encoding="utf-8")
        workspace = (frontend / "components" / "RunWorkspace.tsx").read_text(encoding="utf-8")
        configuration = (frontend / "components" / "RunConfiguration.tsx").read_text(
            encoding="utf-8"
        )
        review = (frontend / "components" / "CanonicalPlanReview.tsx").read_text(encoding="utf-8")
        packages = (frontend / "pages" / "ActionPackages.tsx").read_text(encoding="utf-8")
        provider = (frontend / "components" / "ProviderSetup.tsx").read_text(encoding="utf-8")
        usage = (frontend / "components" / "ProviderAuthorizationReview.tsx").read_text(
            encoding="utf-8"
        )
        authorization = (frontend / "lib" / "provider-authorization.ts").read_text(encoding="utf-8")
        progress = (frontend / "lib" / "run-progress-presentation.ts").read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return False
    job_review = workspace.split("function JobApprovalGate(", 1)[-1]
    review_control = "<CanonicalPlanReview "
    approval_controls = '<div className="job-approval-controls">'
    primary_review = "What this run will do"
    permitted_methods = "All permitted methods, effects and parameters"
    raw_review = "Raw complete approval envelope"
    usage_submission = usage.split("mutationFn: async () => {", 1)[-1].split("onSuccess:", 1)[0]
    return bool(
        "Behavior palette width" in builder
        and "Node inspector width" in builder
        and 'label="Environment profile"' in configuration
        and "<legend>Requested access</legend>" in configuration
        and "function JobApprovalGate(" in workspace
        and review_control in job_review
        and approval_controls in job_review
        and job_review.index(review_control) < job_review.index(approval_controls)
        and "I approve this exact immutable" in job_review
        and 'label="Operator identity for this job"' in job_review
        and "disabled={!exactEnvelopeReady || !confirmed || !approvedBy.trim() || pending}"
        in job_review
        and "if (deadline.recheck()) onApprove();" in job_review
        and all(value in review for value in (primary_review, permitted_methods, raw_review))
        and review.index(primary_review) < review.index(permitted_methods)
        and review.index(permitted_methods) < review.index(raw_review)
        and _imports(provider, "ProviderAuthorizationReview", "./ProviderAuthorizationReview")
        and _imports(provider, "matchingAuthorization", "../lib/provider-authorization")
        and "<ProviderAuthorizationReview " in provider
        and "provider={document} snapshot={authorizations.data}" in provider
        and 'matchingAuthorization(document, authorizations.isError ? undefined : authorizations.data, now, "bluefire_connection_check")'
        in provider
        and "disabled={busy || !valid || !liveReady}" in provider
        and _imports(usage, "authorizationStatus", "../lib/provider-authorization")
        and _imports(usage, "hasRequiredDataPolicy", "../lib/provider-authorization")
        and "export function ProviderAuthorizationReview(" in usage
        and "if (disabled || !valid || !confirmed || !contextCurrent || !hasRequiredDataPolicy(provider) || (loopback && !localConfirmed)) throw"
        in usage_submission
        and "await prepareProvider();" in usage_submission
        and "return api.authorizeAI({ provider, purposes: [...purposes]," in usage_submission
        and 'data_scope: "reviewed_lab_context"' in usage_submission
        and "usage_authorized: true, local_endpoint_authorized: loopback" in usage_submission
        and all(
            guard in authorization
            for guard in (
                "export function matchingAuthorization(",
                "sameJson(row.provider, provider)",
                'authorizationStatus(row, snapshot, now) === "active"',
                "row.purposes.includes(purpose)",
                'row.status !== "active"',
                "row.context.binding_digest !== snapshot.context.binding_digest",
                "row.expires_at_ms <= now",
                "row.usage.requests >= row.limits.max_requests",
                "row.usage.request_bytes >= row.limits.max_request_bytes",
                "row.usage.reserved_output_tokens >= row.limits.max_reserved_output_tokens",
            )
        )
        and _imports(workspace, "recordedStepLabels", "../lib/run-progress-presentation")
        and _imports(workspace, "runEventPresentation", "../lib/run-progress-presentation")
        and "recordedStepLabels(step, catalog, run)" in workspace
        and "runEventPresentation(event, catalog, run, job?.request?.mode)" in workspace
        and "export function recordedStepLabels(" in progress
        and "export function runEventPresentation(" in progress
        and "? object(event.data) : event" in progress
        and "stepOutcomeLabel(step, mode)" in progress
        and "raw editor" not in packages.lower()
        and not re.search(
            r'(?:label|aria-label)=["\'](?:raw )?(?:shell|command)(?: input)?["\']',
            "\n".join((builder, workspace, configuration, review, packages, provider, usage)),
            re.IGNORECASE,
        )
    )


def _imports(source: str, symbol: str, module: str) -> bool:
    return bool(
        re.search(
            rf"import\s*\{{[^}}]*\b{re.escape(symbol)}\b[^}}]*\}}\s*from\s*"
            rf"[\"']{re.escape(module)}[\"']",
            source,
        )
    )
