import { afterEach, expect, it, vi } from "vitest";
import { request } from "../src/lib/api";
import { adSmbApi, checkedAdEnvironments, checkedAdList } from "../src/lib/ad-smb";
import { checkedFileAccessList, checkedFileAccessStatus, fileAccessApi } from "../src/lib/file-access";

vi.mock("../src/lib/api", () => ({ DEMO_MODE: true, request: vi.fn() }));
afterEach(() => vi.clearAllMocks());

it("shows empty unavailable AD readiness without making any local service request", async () => {
  expect(checkedAdEnvironments(await adSmbApi.environments())).toEqual({ nativeAvailable: false, environments: [] });
  expect(checkedAdList(await adSmbApi.list())).toEqual([]);
  expect(request).not.toHaveBeenCalled();
});

it("shows empty unavailable file-access readiness without inventing an enrollment", async () => {
  expect(checkedFileAccessStatus(await fileAccessApi.status())).toMatchObject({ available: false, enrollment: null, allowed_operations: [], problem: { code: "demo_no_enrollment" } });
  expect(checkedFileAccessList(await fileAccessApi.list()).controls).toEqual([]);
  expect(request).not.toHaveBeenCalled();
});

it.each([
  () => adSmbApi.workflow("saved"),
  () => adSmbApi.job("saved"),
  () => adSmbApi.create({ submission_id: "saved", environment_id: "unavailable" }),
  () => adSmbApi.review("saved", "inspect"),
  () => adSmbApi.submit("saved", { submission_id: "saved", phase: "inspect", review_digest: "unavailable", reviewed_by: "operator" }),
  () => adSmbApi.stop("saved"),
  () => adSmbApi.recover("saved"),
  () => fileAccessApi.control("saved"),
  () => fileAccessApi.operation("saved"),
  () => fileAccessApi.reconciliation("saved", "original"),
  () => fileAccessApi.review({ operation: "create", control_owner_id: null }),
  () => fileAccessApi.submit({ submission_id: "saved", review: { operation: "create", control_owner_id: null }, review_digest: "unavailable", reviewed_by: "operator" }),
  () => fileAccessApi.reconcile("saved", { submission_id: "original", expected_outcome_digest: "unavailable", reviewed_by: "operator" }),
])("refuses saved-work and operation requests in demo mode before transport", async action => {
  await expect(action()).rejects.toThrow(/Demo mode/);
  expect(request).not.toHaveBeenCalled();
});
