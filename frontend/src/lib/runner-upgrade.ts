import type { RunnerLifecycleStatus } from "../types";

export interface RunnerUpgradeIdentity {
  runner_id: string;
  runner_version: string;
  product_version: string;
  binary_digest: string;
  platform: string;
  architecture: string;
  inventory_schema: string;
  action_sdk_version: string;
  receipt_protocol: string;
}

export interface RunnerUpgradeReview {
  schema_version: "bluefire.runner-upgrade-review.v1";
  review_digest: string;
  recovery_required?: true;
  current: RunnerUpgradeIdentity;
  candidate: RunnerUpgradeIdentity;
  compatibility: { same_sandbox: true; same_enrollment: true; same_profiles: true; same_protocols: true };
  history: { total_rows: number; execute_rows: number; completed_executions: number; undispatched_executions: number; durable_results: number; ledger_generation: string | null; history_digest: string };
  preservation: { old_binary: true; ledger: true; durable_results: true; product_history: true };
  staging: { candidate_verified: true; activated: false; execution_started: false };
}

export function canReviewRunnerUpgrade(profileId: string | undefined, status: RunnerLifecycleStatus | undefined): boolean {
  return Boolean(profileId && status?.profile_id === profileId && status.enrollment === "active" && status.process === "absent" && (status.state === "stopped" || status.state === "unavailable" && status.upgrade_recovery_required === true));
}

/** A partial or differently bound response must never become an apply control. */
export function isReviewedRunnerUpgrade(review: RunnerUpgradeReview, runnerId: string): boolean {
  const identities = [review?.current, review?.candidate];
  return review?.schema_version === "bluefire.runner-upgrade-review.v1"
    && (review.recovery_required === undefined || review.recovery_required === true)
    && /^sha256:[0-9a-f]{64}$/.test(review.review_digest)
    && identities.every(identity => identity?.runner_id === runnerId && [identity.runner_version, identity.product_version, identity.binary_digest, identity.platform, identity.architecture, identity.inventory_schema, identity.action_sdk_version, identity.receipt_protocol].every(value => typeof value === "string" && value.length > 0))
    && identities.every(identity => /^sha256:[0-9a-f]{64}$/.test(identity.binary_digest))
    && review.compatibility?.same_sandbox === true && review.compatibility.same_enrollment === true && review.compatibility.same_profiles === true && review.compatibility.same_protocols === true
    && ["platform", "architecture", "inventory_schema", "action_sdk_version", "receipt_protocol"].every(key => review.current[key as keyof RunnerUpgradeIdentity] === review.candidate[key as keyof RunnerUpgradeIdentity])
    && review.preservation?.old_binary === true && review.preservation.ledger === true && review.preservation.durable_results === true && review.preservation.product_history === true
    && review.staging?.candidate_verified === true && review.staging.activated === false && review.staging.execution_started === false
    && [review.history?.total_rows, review.history?.execute_rows, review.history?.completed_executions, review.history?.undispatched_executions, review.history?.durable_results].every(value => typeof value === "number" && Number.isSafeInteger(value) && value >= 0)
    && (review.history?.ledger_generation === null || typeof review.history?.ledger_generation === "string")
    && /^sha256:[0-9a-f]{64}$/.test(review.history?.history_digest ?? "");
}
