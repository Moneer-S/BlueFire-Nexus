import { randomBytes } from "node:crypto";
import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { expect, test, type Page } from "@playwright/test";
import corpus from "../../../tests_platform/fixtures/s3_audit_reviews_v1.json" with { type: "json" };
import exercise from "../../../tests_platform/fixtures/s3_audit_exercise_v1.json" with { type: "json" };
import type { AssistanceEnvelope, AssistanceRequest } from "../../src/lib/assistance";
import { checkedAuditAssistanceContext } from "../../src/lib/audit-assistance";

const output = process.env.BLUEFIRE_S3_BROWSER_OUTPUT!;
const review = corpus.cases[0]!.review;
const owner = corpus.history.workflow_job_id;
const selected = { kind: "s3_audit_review" as const, workflow_job_id: owner, review_id: review.review_id, review_digest: review.review_digest };
const context = checkedAuditAssistanceContext({ schema_version: "bluefire.assistance-context.v1", selected, context_digest: `sha256:${"a".repeat(64)}`, capabilities: [], analysis_only: true, limitations: ["Operator imports do not independently prove collection or effective access."], reference_summary: {
  phase: review.source.phase, runner_source: review.source.provenance, cleanup: review.source.cleanup, collection_provenance: "operator_import",
  reported_delivery_state: review.correlation.audit.reported_delivery_state, source_event_count: review.correlation.audit.source_event_count, counts: review.correlation.audit.counts,
  reads: review.correlation.reads.map(row => ({ purpose: row.purpose, reader: row.reader, status: row.status, worker_outcome: row.worker_outcome, matched_event_count: row.audit_event_ids.length, full_object_bytes_proven: false })),
  independent_collection_proven: false, effective_access_claim: false,
} }, selected);
const answer = "One imported record matches the synthetic read. Collection and effective access remain unproven.";
const provider = { provider_id: "audit-browser-fixture", kind: "chat_completions", model: "synthetic-no-model-call", health: { state: "ready", credential_available: true } };

async function fixture(page: Page) {
  const origin = `http://127.0.0.1:${process.env.BLUEFIRE_S3_BROWSER_PORT}`;
  const code = randomBytes(32).toString("hex"), session = randomBytes(32).toString("hex");
  const state = { connected: false, submissions: 0, contextReads: 0, turnReads: 0, allowRead: false, unexpected: [] as string[], pageErrors: [] as string[], sockets: 0 };
  let saved: AssistanceEnvelope | undefined;
  page.on("pageerror", error => state.pageErrors.push(error.message));
  await page.context().routeWebSocket("**/*", socket => { state.sockets++; socket.close(); });
  await page.context().route("**/*", async route => {
    const req = route.request(), url = new URL(req.url()), method = req.method();
    const json = (value: unknown, status = 200) => route.fulfill({ status, contentType: "application/json", body: JSON.stringify(value) });
    if (url.origin !== origin || url.username || url.password || url.search) { state.unexpected.push(method + " " + url.pathname); await route.abort(); return; }
    if (method === "GET" && /^\/ui\/(?:[a-zA-Z0-9_.-]+)?$/.test(url.pathname)) { await route.continue(); return; }
    if (url.pathname === "/api/v1/session") {
      if (method === "POST" && !state.connected && req.headers()["x-bluefire-browser-bootstrap"] === code) { state.connected = true; await json({ session }); return; }
      if (method === "GET" && state.connected && req.headers()["x-bluefire-session"] === session) { await route.fulfill({ status: 204 }); return; }
      if (method === "GET" && !state.connected) { await json({ error: { code: "browser_session_unavailable", message: "Synthetic session required." } }, 401); return; }
    }
    if (!state.connected || req.headers()["x-bluefire-session"] !== session) { state.unexpected.push("session"); await route.abort(); return; }
    if (method === "GET" && url.pathname === "/api/v1/resources/runner-profiles") { await json({ schema_version: "bluefire.resource-list.v1", kind: "runner-profiles", resources: [] }); return; }
    if (method === "GET" && url.pathname === "/api/v1/catalog") { await json({ behaviors: [], actions: [], runner_profiles: [], runners: [], ai: { providers: [provider] } }); return; }
    if (method === "GET" && url.pathname === "/api/v1/scenarios") { await json({ scenarios: [] }); return; }
    if (method === "GET" && url.pathname === "/api/v1/s3-access/environments") { await json({ schema_version: "bluefire.s3-environments.v1", environments: [], problem: "No S3 environment is enrolled." }); return; }
    if (method === "GET" && url.pathname === "/api/v1/s3-access/exercises") { await json({ schema_version: "bluefire.s3-exercise-list.v1", exercises: [], truncated: false }); return; }
    if (method === "GET" && url.pathname === `/api/v1/s3-access/exercises/${owner}`) { await json(exercise); return; }
    if (method === "GET" && url.pathname === `/api/v1/s3-access/exercises/${owner}/audit-reviews`) { await json(corpus.history); return; }
    if (method === "GET" && url.pathname === `/api/v1/s3-access/exercises/${owner}/audit-reviews/${review.review_id}`) { await json(review); return; }
    if (method === "GET" && url.pathname === `/api/v1/s3-access/exercises/${owner}/audit-reviews/${review.review_id}/assistant-context`) { state.contextReads++; await json(context); return; }
    if (method === "POST" && url.pathname === "/api/v1/assistance/turns") {
      const body = req.postDataJSON() as AssistanceRequest;
      expect(Object.keys(body).sort()).toEqual(["autonomy", "context_digest", "message", "provider_id", "selection", "submission_id"]);
      expect(body).toMatchObject({ selection: selected, context_digest: context.context_digest, autonomy: "auto", provider_id: provider.provider_id, message: "Explain what is missing from this review." });
      expect(body.submission_id).toMatch(/^[0-9a-f-]{36}$/);
      saved = { job: { schema_version: "bluefire.job.v1", kind: "assistance.turn", job_id: `job-${body.submission_id.replaceAll("-", "")}`, state: "completed", request: { submitted_request: body }, progress: {} }, turn: { schema_version: "bluefire.assistance-turn.v1", status: "completed", can_start_new_turn: true, message: answer, context_digest: context.context_digest, selected, plan: [], active_child: null, next_action: null, results: [], continuation: null, limitations: context.limitations } };
      state.submissions++; await route.abort("failed"); return;
    }
    if (method === "GET" && saved && url.pathname === `/api/v1/assistance/turns/${saved.job.job_id}`) {
      state.turnReads++;
      await json(state.allowRead ? saved : { error: { code: "temporarily_unavailable", message: "Synthetic lost-response recovery pending." } }, state.allowRead ? 200 : 503); return;
    }
    state.unexpected.push(method + " " + url.pathname); await route.abort();
  });
  await page.goto(`./#/s3-access?exercise=${owner}`);
  await page.getByLabel("One-time connection code", { exact: false }).fill(code);
  await page.getByRole("button", { name: "Connect", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Imported cloud audit", exact: true })).toBeVisible();
  return state;
}

async function capture(page: Page, name: string) {
  await page.evaluate(async () => { await document.fonts.ready; });
  const bounds = await page.evaluate(() => {
    const panel = document.getElementById("experiment-assistant")!, rect = panel.getBoundingClientRect();
    const outside = [...panel.querySelectorAll("h2,h3,p,button,select,textarea,a")].filter(node => { const box = node.getBoundingClientRect(); return box.width > 0 && box.height > 0 && (box.left < rect.left - 1 || box.right > rect.right + 1); }).map(node => node.tagName);
    return { width: document.documentElement.clientWidth, scroll: document.documentElement.scrollWidth, panelWidth: panel.clientWidth, panelScroll: panel.scrollWidth, outside };
  });
  expect(bounds.scroll).toBeLessThanOrEqual(bounds.width); expect(bounds.panelScroll).toBeLessThanOrEqual(bounds.panelWidth); expect(bounds.outside).toEqual([]);
  await page.screenshot({ path: join(output, `${name}.png`), fullPage: false, animations: "disabled" });
  writeFileSync(join(output, `${name}.json`), JSON.stringify({ proof: "synthetic API production UI only; no model call", bounds }, null, 2), { flag: "wx" });
}

for (const width of [1366, 390, 320]) {
  test(`saved audit explanation and lost-response recovery at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: width < 500 ? 844 : 900 });
    const state = await fixture(page);
    await page.getByRole("button", { name: /Baseline reads.*Probe/ }).click();
    await page.getByRole("button", { name: "Explain review", exact: true }).click();
    const panel = page.getByRole("complementary", { name: "Experiment assistant" });
    await expect(panel).toBeVisible();
    await expect.poll(() => state.contextReads).toBe(1);
    expect(state.submissions).toBe(0);
    const semantics = await page.locator("#experiment-assistant").evaluate(element => ({ labelledby: element.getAttribute("aria-labelledby"), heading: document.getElementById("assistant-title")?.textContent, headings: document.querySelectorAll("#assistant-title").length }));
    writeFileSync(join(output, `audit-assistant-semantics-${width}.json`), JSON.stringify(semantics, null, 2), { flag: "wx" });
    await expect(page.locator("#experiment-assistant")).toHaveAccessibleName("Experiment assistant");
    await panel.getByRole("combobox", { name: "AI mode", exact: true }).selectOption("auto");
    await panel.getByRole("combobox", { name: "Provider", exact: true }).selectOption(provider.provider_id);
    await panel.getByRole("textbox", { name: "What would you like to do?", exact: true }).fill("Explain what is missing from this review.");
    await capture(page, `audit-assistant-composer-${width}`);
    await panel.getByRole("button", { name: "Start work", exact: true }).click();
    await expect.poll(() => state.submissions).toBe(1);
    await expect.poll(() => state.turnReads).toBeGreaterThan(0);
    const receipt = await page.evaluate(() => Object.values(sessionStorage).join("\n"));
    expect(receipt).toContain(review.review_digest); expect(receipt).not.toContain(corpus.cases[0]!.input.logs[0]!.data);
    state.allowRead = true;
    await page.reload();
    await expect(panel.getByText(answer, { exact: true })).toBeVisible();
    await expect(panel.getByRole("link", { name: "Saved cloud exercise", exact: true })).toHaveAttribute("href", `#/s3-access?exercise=${owner}`);
    await expect(panel.getByRole("link", { name: /Source rule and evidence/ })).toHaveCount(0);
    await panel.getByText(answer, { exact: true }).scrollIntoViewIfNeeded();
    await capture(page, `audit-assistant-recovered-${width}`);
    await panel.getByRole("button", { name: "Close assistant", exact: true }).click();
    await expect(panel).toHaveCount(0);
    await page.getByRole("button", { name: "Assistant: Completed", exact: true }).click();
    await expect(panel.getByText(answer, { exact: true })).toBeVisible();
    expect(state.submissions).toBe(1); expect(state.unexpected).toEqual([]); expect(state.pageErrors).toEqual([]); expect(state.sockets).toBe(0);
    writeFileSync(join(output, `audit-assistant-journey-${width}.json`), JSON.stringify({ proof: "synthetic API production UI only", cloud_calls: 0, model_calls: 0, real_service: false, state }, null, 2), { flag: "wx" });
  });
}
