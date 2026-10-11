import { expect, test, type Page } from "@playwright/test";
import type { S3Review } from "../../src/lib/s3-access";
import { assertVerticalCapture, capture, desktop, fixture, mobile, report, snapshot } from "../s3-fixture-browser-support";

async function approveReview(page: Page, review: S3Review, cleanup: boolean) {
  const section = page.locator(".s3-review");
  const objects = page.getByRole("region", { name: "Generated test objects", exact: true });
  await expect(objects.getByRole("heading", { name: "Sample records", exact: true })).toBeVisible();
  await expect(objects.getByRole("heading", { name: "Legitimate-use canary", exact: true })).toBeVisible();
  await expect(section.getByText(`${review.reserved.api_calls} / ${review.remaining.api_calls} remaining`, { exact: true })).toBeVisible();
  const allowance = page.getByLabel("Follow-up allowance", { exact: true });
  const reserved = review.reserved.api_calls, required = review.required_remaining.api_calls;
  if (typeof reserved !== "number" || typeof required !== "number") throw new Error("The saved API allowance is missing.");
  await expect(allowance.getByText(String(required - reserved), { exact: true })).toBeVisible();
  const details = section.getByLabel("Test object review", { exact: true }).locator("details");
  await expect(details).toHaveCount(2);
  await details.first().locator("summary").click();
  await expect(details.first().locator("pre")).toHaveText(review.fixture_lifecycle!.objects[0]!.payload_preview);
  await details.first().locator("summary").click();
  const confirm = page.getByRole("button", { name: "Confirm stage", exact: true });
  await expect(confirm).toBeDisabled();
  await page.getByLabel("Reviewed by", { exact: true }).fill("synthetic operator");
  await expect(confirm).toBeDisabled();
  await page.getByRole("checkbox", { name: cleanup ? "I approve removing these test objects and retaining the current policy." : "I approve this exact stage and its reserved limits.", exact: true }).check();
  await expect(confirm).toBeEnabled();
  return confirm;
}

test("synthetic fixture preparation: exact review, pending reload and Stop never replay", async ({ page }) => {
  const initial = snapshot("initial");
  const state = await fixture(page, initial);
  const objects = page.getByRole("region", { name: "Generated test objects", exact: true });
  await expect(objects.getByText("Not observed", { exact: true })).toHaveCount(2);
  for (const viewport of [desktop, mobile]) assertVerticalCapture(await capture(page, "fixture-initial", viewport));
  expect(state.counts.stage).toBe(0);
  await page.getByRole("button", { name: "Prepare test objects", exact: true }).click();
  const confirm = await approveReview(page, initial.review!, false);
  await confirm.evaluate(node => node.scrollIntoView({ behavior: "instant", block: "center" }));
  assertVerticalCapture(await capture(page, "fixture-prepare-review", mobile, ".s3-review > button"), true);
  await confirm.click();
  await expect(page.getByText("Original operation in progress", { exact: true })).toBeVisible();
  await page.reload();
  await expect(page.getByText("Original operation in progress", { exact: true })).toBeVisible();
  expect(state.counts.stage).toBe(1);
  await page.getByRole("button", { name: "Stop current operation", exact: true }).click();
  await expect(page.getByRole("button", { name: "Retry stop", exact: true })).toBeEnabled();
  await page.reload();
  await expect(page.getByRole("button", { name: "Retry stop", exact: true })).toBeEnabled();
  assertVerticalCapture(await capture(page, "fixture-prepare-stopped", mobile));
  expect(state.counts).toEqual({ review: 1, stage: 1, stop: 1, recover: 0, unexpected: 0, pageErrors: 0, websocket: 0 });
  report("fixture-prepare", { counts: state.counts, original_corpus: "initial", submitted_effect: "synthetic pending only" });
});

test("synthetic fixture cleanup: object removal review retains accepted policy", async ({ page }) => {
  const owned = snapshot("owned");
  const state = await fixture(page, owned);
  const objects = page.getByRole("region", { name: "Generated test objects", exact: true });
  await expect(objects.getByText("Synthetic observation", { exact: true })).toHaveCount(2);
  await expect(page.getByText("No live defensive effectiveness has been independently verified.", { exact: true })).toBeVisible();
  for (const viewport of [desktop, mobile]) assertVerticalCapture(await capture(page, "fixture-owned", viewport));
  await page.getByRole("button", { name: "Remove test objects", exact: true }).click();
  await expect(page.getByText("Only these test objects will be removed. The current policy is retained.", { exact: true })).toBeVisible();
  await expect(page.getByLabel("Test object review", { exact: true }).getByText("Hardened; retained", { exact: true })).toBeVisible();
  const confirm = await approveReview(page, owned.review!, true);
  await confirm.evaluate(node => node.scrollIntoView({ behavior: "instant", block: "center" }));
  assertVerticalCapture(await capture(page, "fixture-cleanup-review", mobile, ".s3-review > button"), true);
  await confirm.click();
  await expect(page.getByText("Original operation in progress", { exact: true })).toBeVisible();
  await page.reload();
  await expect(page.getByText("Original operation in progress", { exact: true })).toBeVisible();
  await expect(objects.getByText("Synthetic observation", { exact: true })).toHaveCount(2);
  expect(state.counts).toEqual({ review: 1, stage: 1, stop: 0, recover: 0, unexpected: 0, pageErrors: 0, websocket: 0 });
  report("fixture-cleanup", { counts: state.counts, original_corpus: "owned", submitted_effect: "synthetic pending only", policy_rollback_requested: false });
});

test("synthetic saved fixture outcomes: unresolved, partial and absent states remain distinct", async ({ page }) => {
  const names = ["uncertain", "partial_cleanup", "absent_retained_policy"];
  const state = await fixture(page, snapshot(names[0]!));
  for (const [index, name] of names.entries()) {
    if (index) { state.replace(snapshot(name)); await page.reload(); }
    const objects = page.getByRole("region", { name: "Generated test objects", exact: true });
    await expect(objects.getByText("Synthetic observation", { exact: true })).toHaveCount(2);
    await expect(objects.getByText("Policy retained", { exact: true })).toBeVisible();
    const stages = page.getByLabel("Available stages", { exact: true });
    if (name === "uncertain") {
      await expect(stages.getByRole("button")).toHaveCount(1);
      await expect(stages.getByRole("button", { name: "Check test objects", exact: true })).toBeVisible();
      await expect(objects.getByText("Needs reconciliation", { exact: true })).toHaveCount(2);
    } else if (name === "partial_cleanup") {
      await expect(stages.getByRole("button")).toHaveCount(2);
      await expect(stages.getByRole("button", { name: "Remove test objects", exact: true })).toBeVisible();
      await expect(objects.getByText("Verified absent", { exact: true })).toHaveCount(1);
      await expect(objects.getByText("Verified present", { exact: true })).toHaveCount(1);
    } else {
      await expect(stages.getByRole("button")).toHaveCount(0);
      await expect(objects.getByText("Verified absent", { exact: true })).toHaveCount(3);
      await expect(page.getByText("Removed", { exact: true })).toBeVisible();
    }
    await expect(page.getByRole("link", { name: "Run evidence 1", exact: true }).first()).toHaveAttribute("href", /^#\/runs\/run-/);
    for (const viewport of [desktop, mobile]) assertVerticalCapture(await capture(page, `fixture-${name}`, viewport));
    await page.reload();
    await expect(page.getByRole("region", { name: "Generated test objects", exact: true })).toBeVisible();
    expect(state.counts.stage).toBe(0);
  }
  expect(state.counts).toEqual({ review: 0, stage: 0, stop: 0, recover: 0, unexpected: 0, pageErrors: 0, websocket: 0 });
  report("fixture-saved-outcomes", { counts: state.counts, original_corpus_states: names, independent_saved_snapshots_not_a_claimed_execution_sequence: true });
});
