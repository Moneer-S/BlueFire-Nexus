import { describe, expect, it } from "vitest";
import { classifyRequest, consumeRequestBudget } from "./installed/receiver-guards.mjs";

const origin = "http://127.0.0.1:4317";
const limits = { stop: 1 };

describe("installed receiver request guards", () => {
  it("authorizes an allowlisted POST independently of read allowlists", () => {
    const counts = { stop: 0 };
    const decision = classifyRequest({
      origin,
      expectedOrigin: origin,
      method: "POST",
      url: new URL(`${origin}/api/v1/runner/stop`),
      body: { profile_id: "sandbox-endpoint-deep-lab.v1" },
      allowedRead: () => false,
      authorizePost: () => consumeRequestBudget(counts, limits, "stop"),
    });

    expect(decision).toEqual({ allowed: true });
    expect(counts.stop).toBe(1);
  });

  it("rejects denied origins, malformed bodies, unlisted methods, and exhausted budgets", () => {
    const url = new URL(`${origin}/api/v1/runner/stop`);
    const base = { expectedOrigin: origin, url, body: {}, allowedRead: () => false, authorizePost: () => true };

    expect(classifyRequest({ ...base, origin: "https://example.invalid", method: "GET" })).toEqual({ allowed: false, reason: "non_loopback" });
    expect(classifyRequest({ ...base, origin, method: "POST", bodyError: true })).toEqual({ allowed: false, reason: "invalid_json_body" });
    expect(classifyRequest({ ...base, origin, method: "PUT" })).toEqual({ allowed: false, reason: "method_not_allowlisted" });

    const counts = { stop: 1 };
    expect(consumeRequestBudget(counts, limits, "stop")).toBe(false);
    expect(counts.stop).toBe(1);
  });

  it("caps the five phase approvals and the two owner creations independently", () => {
    const limits = { owner: 2, prepare: 5, review: 5, approval: 5 };
    const counts = { owner: 0, prepare: 0, review: 0, approval: 0 };
    for (let index = 0; index < 5; index += 1) {
      expect(consumeRequestBudget(counts, limits, "prepare")).toBe(true);
      expect(consumeRequestBudget(counts, limits, "review")).toBe(true);
      expect(consumeRequestBudget(counts, limits, "approval")).toBe(true);
    }
    expect(consumeRequestBudget(counts, limits, "prepare")).toBe(false);
    expect(consumeRequestBudget(counts, limits, "review")).toBe(false);
    expect(consumeRequestBudget(counts, limits, "approval")).toBe(false);
    expect(consumeRequestBudget(counts, limits, "owner")).toBe(true);
    expect(consumeRequestBudget(counts, limits, "owner")).toBe(true);
    expect(consumeRequestBudget(counts, limits, "owner")).toBe(false);
    expect(counts).toEqual({ owner: 2, prepare: 5, review: 5, approval: 5 });
  });
});
