import type { RunnerUpgradeReview } from "../src/lib/runner-upgrade";

export const upgradeDigest = `sha256:${"a".repeat(64)}`;
export function runnerUpgradeReview(runnerId = "bluefire-rust-runner.v1"): RunnerUpgradeReview {
  const identity = { runner_id: runnerId, runner_version: "3.0.0", product_version: "3.0.0", binary_digest: `sha256:${"b".repeat(64)}`, platform: "linux", architecture: "x86_64", inventory_schema: "bluefire.runner-inventory.v1", action_sdk_version: "bluefire.runner-action-sdk.v1", receipt_protocol: "bluefire.runner-receipt-wal.v2" };
  return {
    schema_version: "bluefire.runner-upgrade-review.v1", review_digest: upgradeDigest,
    current: { ...identity }, candidate: { ...identity, binary_digest: `sha256:${"c".repeat(64)}` },
    compatibility: { same_sandbox: true, same_enrollment: true, same_profiles: true, same_protocols: true },
    history: { total_rows: 8, execute_rows: 3, completed_executions: 2, undispatched_executions: 1, durable_results: 2, ledger_generation: "reviewed-generation", history_digest: `sha256:${"d".repeat(64)}` },
    preservation: { old_binary: true, ledger: true, durable_results: true, product_history: true },
    staging: { candidate_verified: true, activated: false, execution_started: false },
  };
}
