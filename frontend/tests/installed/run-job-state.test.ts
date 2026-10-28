import { describe, expect, it } from "vitest";
import { waitForRunApproval } from "./run-job-state.mjs";

const jobId = "job-0123456789abcdef0123456789abcdef";

describe("installed run job state polling", () => {
  it("waits through queued and planning until the exact job reaches approval", async () => {
    const states = ["queued", "planning", "awaiting_approval"];
    const queriedIds: string[] = [];
    const timeouts: number[] = [];
    let now = 1_000;

    const job = await waitForRunApproval({
      jobId,
      deadline: 2_000,
      now: () => now,
      readJob: async (id, timeoutMs) => {
        queriedIds.push(id);
        timeouts.push(timeoutMs);
        return { job_id: jobId, state: states.shift() ?? "awaiting_approval" };
      },
      sleep: async milliseconds => { now += milliseconds; },
    });

    expect(job).toEqual({ job_id: jobId, state: "awaiting_approval" });
    expect(queriedIds).toEqual([jobId, jobId, jobId]);
    expect(timeouts).toEqual([1_000, 750, 500]);
  });

  it.each(["failed", "cancelled", "interrupted", "completed", "running"])(
    "stops instead of approving a job in the unexpected %s state",
    async state => {
      await expect(waitForRunApproval({
        jobId,
        deadline: 2_000,
        now: () => 1_000,
        readJob: async id => ({ job_id: id, state }),
        sleep: async () => {},
      })).rejects.toThrow("expected transient states");
    },
  );

  it("rejects a polled response for another job", async () => {
    await expect(waitForRunApproval({
      jobId,
      deadline: 2_000,
      now: () => 1_000,
      readJob: async () => ({ job_id: "job-fedcba9876543210fedcba9876543210", state: "awaiting_approval" }),
      sleep: async () => {},
    })).rejects.toThrow("identity did not match");
  });

  it("stops polling at its deadline while queued", async () => {
    let now = 1_000;
    let reads = 0;

    await expect(waitForRunApproval({
      jobId,
      deadline: 1_500,
      now: () => now,
      readJob: async id => {
        reads += 1;
        return { job_id: id, state: "queued" };
      },
      sleep: async milliseconds => { now += milliseconds; },
    })).rejects.toThrow("bounded deadline");
    expect(reads).toBe(2);
    expect(now).toBe(1_500);
  });

  it("does not accept approval from a poll that returns after the deadline", async () => {
    let now = 1_000;

    await expect(waitForRunApproval({
      jobId,
      deadline: 1_500,
      now: () => now,
      readJob: async id => {
        now = 1_500;
        return { job_id: id, state: "awaiting_approval" };
      },
      sleep: async () => {},
    })).rejects.toThrow("bounded deadline");
  });
});
