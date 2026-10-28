import { beforeEach, describe, expect, it, vi } from "vitest";
import { receiverFixture, receiverFixtureId } from "./receiver-defense-fixture";
import { retainedReceiverFixture } from "./receiver-retained-fixture";
import { adOwner, rawAdWorkflow } from "./ad-smb-fixture";
import { s3Observed, s3Owner } from "./s3-access-fixture";

const { receiverTest, networkRequest, fileControl, checkedFileAccessControl, fileAccessControlIdValid } = vi.hoisted(() => ({
  receiverTest: vi.fn(), networkRequest: vi.fn(),
  fileControl: vi.fn(), checkedFileAccessControl: vi.fn<(value: unknown, id?: string) => unknown>(value => value),
  fileAccessControlIdValid: vi.fn((value: string) => /^file-control-[0-9a-f]{64}$/.test(value) || /^job-[0-9a-f]{32}$/.test(value)),
}));

vi.mock("../src/lib/api", () => ({ DEMO_MODE: false, request: networkRequest, api: { receiverTest } }));
vi.mock("../src/lib/file-access", () => ({ fileAccessApi: { control: fileControl }, checkedFileAccessControl, fileAccessControlIdValid,
  fileAccessOperationLabels: { create: "Create file", baseline: "Baseline reads", harden: "Harden file", rollback: "Restore file", reset: "Reset file" } }));
vi.mock("../src/lib/saved-defensive-work", () => ({ workFamilies: [
  { id: "handoff", label: "Data handoff", href: "/compare?receiver=1" },
  { id: "file", label: "File access", href: "/file-access" },
  { id: "domain", label: "Domain access", href: "/ad-smb" },
  { id: "cloud", label: "S3 access", href: "/s3-access" },
] }));

import { loadActiveWork } from "../src/lib/active-defensive-work";

describe("loadActiveWork", () => {
  beforeEach(() => { vi.restoreAllMocks(); vi.clearAllMocks(); });

  it("fetches the selected saved record by id through its read endpoint and validates the returned identity", async () => {
    const selectedId = receiverFixtureId;
    const record = retainedReceiverFixture("protected", "idle");
    const before = structuredClone(record);
    receiverTest.mockResolvedValue(record);

    const summary = await loadActiveWork({ family: "handoff", id: selectedId });

    expect(receiverTest).toHaveBeenCalledOnce();
    expect(receiverTest).toHaveBeenCalledWith(selectedId);
    expect(summary.href).toBe(`/compare?receiver=1&goal=data-handoff&receiver_job=${selectedId}`);
    expect(summary.phase).toBe("Redaction required");
    expect(summary.title).toBe("Controlled data handoff · Public record handoff");
    expect(summary.change).toBe("Desired policy: Accept reviewed synthetic records · Proposed");
    expect(summary.results).toEqual([
      { label: "Baseline", value: "Accepted by the receiver" },
      { label: "Evidence source", value: "Owned loopback receiver decision" },
    ]);
    expect(summary.results).not.toContainEqual(expect.objectContaining({ label: "Independent observation" }));
    expect(summary.links).toEqual([
      { label: "Open saved experiment", href: "/builder?saved_scenario=receiver-collection&version=1&digest=sha256%3Aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" },
      { label: "Baseline run evidence", href: "/runs/run-baseline" },
    ]);
    expect(summary.runContexts).toEqual([{ runId: "run-baseline", phase: "Baseline", receiverDecision: "Accepted by the receiver" }]);
    expect(record).toEqual(before);
  });

  it("keeps domain provenance separate from recorded cleanup and does not claim a missing change", async () => {
    const raw = rawAdWorkflow({ phases: ["harden", "retest"], expectation: "matched" });
    const execution = raw.workflow.progress.operations[1]!.executions[0] as { provenance: string };
    execution.provenance = "runner_reported";
    networkRequest.mockResolvedValueOnce(raw);

    const summary = await loadActiveWork({ family: "domain", id: adOwner });

    expect(summary.title).toBe("Excess domain access · lab.example.test · member.lab.example.test");
    expect(summary.results).toHaveLength(4);
    expect(summary.results).toContainEqual({ label: "Execution source", value: "Synthetic fixture; Runner-reported" });
    expect(summary.results).toContainEqual({ label: "Cleanup", value: "Verified" });
    expect(summary.results).toContainEqual({ label: "Recorded reads", value: "probe primary: Open access denied; legitimate primary: Bytes matched; legitimate health: Bytes matched" });
    expect(summary.change).toBe("Recorded policy: Hardened");
    expect(summary.links).toEqual([{ label: "Open saved domain run", href: "/runs/run-ad-retest" }]);
    expect(networkRequest).toHaveBeenCalledOnce();
  });

  it("shows policy retention independently from cleanup uncertainty", async () => {
    const selectedId = s3Owner;
    const record = s3Observed();
    record.policy_state = "hardened";
    record.allowed_phases = [];
    record.operations[0]!.outcome.cleanup = "unknown";
    const retest = structuredClone(record.operations[0]!);
    retest.phase = "retest";
    retest.operation_job_id = `job-${"3".repeat(32)}`;
    retest.run_ids = ["run-20261009T000000Z-5555555555555555"];
    record.operations.push(retest);
    networkRequest.mockResolvedValueOnce(record);

    const summary = await loadActiveWork({ family: "cloud", id: selectedId });

    expect(networkRequest).toHaveBeenCalledOnce();
    expect(summary.results).toHaveLength(4);
    expect(summary.results).toContainEqual({ label: "Result source", value: "Synthetic fixture" });
    expect(summary.results).toContainEqual({ label: "Cleanup and resources", value: "Worker cleanup: Unknown; resources: Retained" });
    expect(summary.results).toContainEqual({ label: "Recorded reads and independent observations", value: "probe primary: read; legitimate primary: read; legitimate health: read · 0 independent observations" });
    expect(summary.change).toBe("Recorded policy: Hardened");
    expect(summary.links).toEqual([
      { label: "Baseline reads run evidence", href: "/runs/run-20261009T000000Z-3333333333333333" },
      { label: "Fresh access checks run evidence", href: "/runs/run-20261009T000000Z-5555555555555555" },
    ]);
  });

  it("uses platform and resource context for a saved file control", async () => {
    const selectedId = `file-control-${"4".repeat(64)}`;
    const record = { status: "hardened", platform: "windows", resource: { protection: "metadata_only", record_count: 12 },
      baseline: {}, operations: [], task_usage_state: "settled" };
    fileControl.mockResolvedValue(record);
    checkedFileAccessControl.mockImplementation((value: unknown, id?: string) => {
      expect(value).toBe(record);
      expect(id).toBe(selectedId);
      return record;
    });

    const summary = await loadActiveWork({ family: "file", id: selectedId });

    expect(fileControl).toHaveBeenCalledWith(selectedId);
    expect(summary.environment).toBe("Protected Windows setup");
    expect(summary.title).toBe("Excess file access · Windows generated file");
    expect(summary.change).toBe("File protection metadata_only");
    expect(summary.results).toContainEqual({ label: "Task usage", value: "settled" });
  });

  it("parses only known families with family-specific valid IDs before building canonical links", async () => {
    const { parseActiveWorkReference, activeWorkHref } = await import("../src/lib/active-defensive-work");
    const valid = { family: "domain", id: `job-${"a".repeat(32)}` } as const;
    expect(parseActiveWorkReference(valid)).toEqual(valid);
    expect(parseActiveWorkReference({ ...valid, timestamp: "untrusted" })).toBeUndefined();
    expect(parseActiveWorkReference({ family: "domain", id: "not-a-job" })).toBeUndefined();
    expect(activeWorkHref(valid)).toBe(`/ad-smb?goal=ad-access&workflow=${valid.id}`);
    await expect(loadActiveWork({ family: "domain", id: "not-a-job" })).rejects.toThrow(/valid saved work item/);
    expect(networkRequest).not.toHaveBeenCalled();
  });

  it("keeps missing stage, policy, outcome, and links unreported for a partial retained item", async () => {
    const id = receiverFixtureId;
    const partial = receiverFixture("baseline", "idle");
    receiverTest.mockResolvedValue(partial);

    const summary = await loadActiveWork({ family: "handoff", id });

    expect(summary.phase).toBe("Baseline");
    expect(summary.change).toBe("Not recorded");
    expect(summary.results).toEqual([
      { label: "Phase outcomes", value: "Not recorded" },
      { label: "Evidence source", value: "Not recorded" },
    ]);
    expect(summary.links).toHaveLength(1);
    expect(summary.runContexts).toEqual([]);
  });

  it("rejects a malformed or mismatched direct response without producing a summary", async () => {
    const selectedId = receiverFixtureId;
    const wrongRecord = receiverFixture("baseline", "idle");
    wrongRecord.job.job_id = `job-${"7".repeat(32)}`;
    receiverTest.mockResolvedValue(wrongRecord);

    await expect(loadActiveWork({ family: "handoff", id: selectedId })).rejects.toThrow(/does not match its saved review/);
    expect(receiverTest).toHaveBeenCalledWith(selectedId);
  });

  it("does not label insufficient evidence as an owned receiver decision even when its state says verified", async () => {
    const record = receiverFixture("baseline", "insufficient");
    record.phases[0]!.result!.receiver_observation.state = "verified";
    receiverTest.mockResolvedValue(record);

    const summary = await loadActiveWork({ family: "handoff", id: receiverFixtureId });

    expect(summary.results).toContainEqual({ label: "Baseline", value: "Not enough evidence" });
    expect(summary.results).toContainEqual({ label: "Evidence source", value: "Not recorded" });
    expect(summary.runContexts).toEqual([{ runId: record.phases[0]!.result!.run_id, phase: "Baseline" }]);
  });

  it("retains exact run bindings for the protective refusal and legitimate-use phases", async () => {
    const record = retainedReceiverFixture("legitimate", "completed");
    receiverTest.mockResolvedValue(record);
    const before = structuredClone(record);
    const summary = await loadActiveWork({ family: "handoff", id: receiverFixtureId });
    expect(summary.runContexts).toEqual(record.phases.map(phase => ({
      runId: phase.result!.run_id,
      phase: phase.phase === "baseline" ? "Baseline" : phase.phase === "protected" ? "Redaction required" : "Legitimate redacted use",
      receiverDecision: phase.phase === "protected" ? "Prevented by the receiver" : "Accepted by the receiver",
    })));
    expect(record).toEqual(before);
  });

  it("labels a rolled-back policy as desired state and does not imply it remains applied", async () => {
    const record = retainedReceiverFixture();
    const rollback = { submission_id: "50000000-0000-4000-8000-000000000000", control_digest: record.control!.control_digest,
      decision: "rollback" as const, reviewed_by: "operator" };
    record.control!.status = "rolled_back";
    record.control!.desired_policy_id = "receiver.reviewed-records.v1";
    record.control!.receiver_state = "stopped";
    record.control!.can_retest = false;
    record.control!.can_rollback = false;
    record.control!.rollback = rollback;
    record.job.progress.control_rollback = rollback;
    receiverTest.mockResolvedValue(record);

    const summary = await loadActiveWork({ family: "handoff", id: receiverFixtureId });

    expect(summary.change).toBe("Desired policy: Accept reviewed synthetic records · Rolled back");
  });
});
