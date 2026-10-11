import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { expect, it, vi } from "vitest";
import productCorpus from "../../tests_platform/fixtures/s3_fixture_product_v2.json";
import { checkedExercise, checkedReview, s3Api, type S3Exercise, type S3Review } from "../src/lib/s3-access";
import { S3AccessPage } from "../src/pages/S3Access";
import { s3Exercise, s3Hash, s3Operation, s3Owner, s3Review } from "./s3-access-fixture";

function fixtureExercise(): S3Exercise {
  const value = s3Exercise();
  value.schema_version = "bluefire.s3-exercise.v2";
  value.environment.fixture_lifecycle = { schema_version: "bluefire.s3-fixture-enrollment.v2", scope_digest: s3Hash, generation_digest: s3Hash, exclusive_writer_digest: s3Hash, bucket_shape: "never_versioned_no_object_lock" };
  value.fixtures = (["primary", "health"] as const).map(purpose => ({ purpose, key: `bluefire/s3-${"a".repeat(32)}/${purpose === "primary" ? "records" : "health"}.jsonl`, state: "not_prepared", etag: null, sha256: s3Hash, size_bytes: 3, intent_id: "b".repeat(64), request_ids: [], provenance: "not_observed" }));
  value.environment.scope.objects = value.fixtures.map(({ purpose, key, sha256, size_bytes }) => ({ purpose, key, sha256, size_bytes }));
  value.fixture_state = "not_prepared";
  value.policy_retention = null;
  value.resource_disposition = "not_prepared";
  value.allowed_phases = ["prepare"];
  return value;
}

function fixtureReview(phase: "prepare" | "cleanup" = "prepare"): S3Review {
  const value = s3Review(phase);
  value.schema_version = "bluefire.s3-stage-review.v2";
  value.fixture_lifecycle = { authority_digest: s3Hash, intent_id: "b".repeat(64), objects: fixtureExercise().fixtures!.map(row => ({ purpose: row.purpose, key: row.key, sha256: row.sha256, size_bytes: row.size_bytes, payload_preview: "{}\n", expected_etag: null })), policy_disposition: "retain_current", policy_state: "hardened" };
  return value;
}

it("accepts the exact versioned fixture projection without expanding legacy work", () => {
  const value = fixtureExercise();
  expect(checkedExercise(value, s3Owner)).toEqual(value);
  expect(() => checkedExercise({ ...value, schema_version: "bluefire.s3-exercise.v1" }, s3Owner)).toThrow();
  const legacy = s3Exercise(); legacy.allowed_phases = ["prepare"];
  expect(() => checkedExercise(legacy, s3Owner)).toThrow();
  expect(() => checkedReview(s3Review("cleanup"), s3Owner, "cleanup")).toThrow();
});

it.each([
  ["missing enrollment", (v: S3Exercise) => { delete v.environment.fixture_lifecycle; }],
  ["missing object", (v: S3Exercise) => { v.fixtures!.pop(); }],
  ["another intent", (v: S3Exercise) => { v.fixtures![1]!.intent_id = "c".repeat(64); }],
  ["another key", (v: S3Exercise) => { v.fixtures![0]!.key = "other.jsonl"; }],
  ["unobserved ownership", (v: S3Exercise) => { v.fixtures![0]!.state = "owned"; }],
  ["false absence", (v: S3Exercise) => { v.resource_disposition = "removed"; }],
  ["unbound retention", (v: S3Exercise) => { v.policy_retention = { policy_state: "hardened", review_digest: "wrong", operation_job_id: s3Operation }; }],
] as const)("refuses %s before presenting fixture status", (_name, change) => {
  const value = fixtureExercise(); change(value);
  expect(() => checkedExercise(value, s3Owner)).toThrow();
});

it("retains explicit recovery after stop, but refuses a new preparation", () => {
  const value = fixtureExercise(); value.stopped = true;
  expect(() => checkedExercise(value, s3Owner)).toThrow();
  value.allowed_phases = ["reconcile_fixtures", "cleanup"];
  expect(checkedExercise(value, s3Owner)).toEqual(value);
});

it("retains repeated bounded service request IDs and prioritizes unresolved mutations", () => {
  const value = fixtureExercise();
  value.fixtures![0]!.state = "uncertain";
  value.fixtures![0]!.provenance = "synthetic";
  value.fixtures![0]!.request_ids = ["SAFE-REQUEST-ID", "SAFE-REQUEST-ID"];
  value.fixtures![1]!.state = "drift";
  value.fixtures![1]!.provenance = "synthetic";
  value.fixture_state = "uncertain";
  value.resource_disposition = "cleanup_required";
  value.allowed_phases = ["reconcile_fixtures"];
  expect(checkedExercise(value, s3Owner)).toEqual(value);
  expect(() => checkedExercise({ ...value, fixture_state: "drift" }, s3Owner)).toThrow();
});

it("requires exact fixture review content and keeps policy stages distinct", () => {
  expect(checkedReview(fixtureReview(), s3Owner, "prepare")).toEqual(fixtureReview());
  const bad = fixtureReview(); bad.fixture_lifecycle!.objects[0]!.size_bytes += 1;
  expect(() => checkedReview(bad, s3Owner, "prepare")).toThrow();
  const policy = s3Review(); policy.schema_version = "bluefire.s3-stage-review.v2"; policy.fixture_lifecycle = null;
  expect(checkedReview(policy, s3Owner, "inspect")).toEqual(policy);
});

it("reviews cleanup and retained policy together without submitting on reload", async () => {
  const value = fixtureExercise();
  value.policy_state = "hardened"; value.fixture_state = "owned"; value.resource_disposition = "retained";
  value.allowed_phases = ["cleanup"];
  value.fixtures!.forEach(row => { row.state = "owned"; row.etag = '"fixture-etag"'; row.provenance = "synthetic"; });
  vi.spyOn(s3Api, "environments").mockResolvedValue({ schema_version: "bluefire.s3-environments.v1", environments: [], problem: null });
  vi.spyOn(s3Api, "list").mockResolvedValue({ schema_version: "bluefire.s3-exercise-list.v1", exercises: [], truncated: false });
  vi.spyOn(s3Api, "read").mockResolvedValue(value);
  vi.spyOn(s3Api, "review").mockResolvedValue(fixtureReview("cleanup"));
  vi.spyOn(s3Api, "send").mockRejectedValue(new Error("Confirmation pending"));
  const user = userEvent.setup();
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[`/s3-access?exercise=${s3Owner}`]}><S3AccessPage /></MemoryRouter></QueryClientProvider>);
  await screen.findByRole("region", { name: "Generated test objects" });
  expect(s3Api.send).not.toHaveBeenCalled();
  await user.click(screen.getByRole("button", { name: "Remove test objects" }));
  expect(await screen.findByText("Only these test objects will be removed. The current policy is retained.")).toBeVisible();
  expect(screen.getByRole("button", { name: "Confirm stage" })).toBeDisabled();
  await user.type(screen.getByLabelText("Reviewed by"), "delegated test reviewer");
  await user.click(screen.getByRole("checkbox", { name: "I approve removing these test objects and retaining the current policy." }));
  await user.click(screen.getByRole("button", { name: "Confirm stage" }));
  await waitFor(() => expect(s3Api.send).toHaveBeenCalledOnce());
  expect(vi.mocked(s3Api.send).mock.calls[0]![0]).toMatchObject({ kind: "stage", request: { phase: "cleanup", review_digest: s3Hash } });
});

it.each(productCorpus.snapshots)("renders the saved product state without dispatching: $name", async snapshot => {
  const value = snapshot.exercise as unknown as S3Exercise;
  vi.spyOn(s3Api, "environments").mockResolvedValue({ schema_version: "bluefire.s3-environments.v1", environments: [], problem: null });
  vi.spyOn(s3Api, "list").mockResolvedValue({ schema_version: "bluefire.s3-exercise-list.v1", exercises: [], truncated: false });
  vi.spyOn(s3Api, "read").mockResolvedValue(checkedExercise(value, value.workflow_job_id));
  vi.spyOn(s3Api, "send");
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[`/s3-access?exercise=${value.workflow_job_id}`]}><S3AccessPage /></MemoryRouter></QueryClientProvider>);
  expect(await screen.findByRole("region", { name: "Generated test objects" })).toBeVisible();
  expect(screen.getByText("Sample records")).toBeVisible();
  expect(s3Api.send).not.toHaveBeenCalled();
  if (value.policy_retention) expect(screen.getByText("Policy retained")).toBeVisible();
});
