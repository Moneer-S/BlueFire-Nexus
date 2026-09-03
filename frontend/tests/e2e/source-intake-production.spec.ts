import { promises as fs } from "node:fs";
import { isAbsolute } from "node:path";
import process from "node:process";
import { URL } from "node:url";
import { expect, test, type Locator, type Page } from "@playwright/test";

const CAPABILITY_FRAGMENT = /^#bluefire-session=[A-Za-z0-9_-]{64}$/;
const LOOPBACK_HOSTS = new Set(["127.0.0.1", "[::1]", "::1"]);
const SOURCE_ID = "research.mitre-attack-enterprise.v1";
const SOURCE_PROJECT = "mitre/cti";
const SOURCE_VERSION = "19.2";
const SOURCE_PIN = "8543c5b05bd9bbcace9fc37f30bba96b675b6f33"; // pragma: allowlist secret -- public Git commit
const SOURCE_LICENSE = "LicenseRef-MITRE-ATTACK-2026";
const SOURCE_CLASSIFICATION = "metadata_import";
const SOURCE_CONTENT_HANDLING = "vendored_declarative";
const SOURCE_PATH = "bluefire/data/mitre_attack_t1082_v19_2.json";
const LICENSE_PATH = "bluefire/data/mitre_attack_v19_2_LICENSE.txt";
const BEHAVIOR_ID = "research.attack.system-information-discovery.v1";
const ACTION_ID = "research.attack.system-information-discovery-action.v1";
const INTAKE_ID = "intake.mitre-t1082.v1";
const INTAKE_DESTINATION_ID = "gate09-browser-reviewed-t1082";
const INTAKE_OPERATOR_ID = "gate-09-browser-reviewer";
const SHA256 = /^sha256:[0-9a-f]{64}$/;
const REQUIRED_NOTICE = "© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation.";
const OPERATION_SEQUENCE = [
  "bootstrap_production_session",
  "open_research_sources",
  "verify_pinned_source",
  "expand_intake_review",
  "configure_reviewed_intake",
  "activate_reviewed_intake",
  "open_behaviors",
  "verify_imported_behavior",
  "verify_behavior_provenance",
  "reload_and_verify_persisted_state",
] as const;

function requiredEnvironment(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`Gate09 browser test is missing ${name}.`);
  return value;
}

function validatedLaunchUrl(): URL {
  let parsed: URL;
  try {
    parsed = new URL(requiredEnvironment("BLUEFIRE_PRODUCTION_URL"));
  } catch {
    throw new Error("Gate09 production launch URL is invalid.");
  }
  if (
    parsed.protocol !== "http:"
    || !LOOPBACK_HOSTS.has(parsed.hostname)
    || parsed.username
    || parsed.password
    || parsed.search
    || !["/", "/index.html"].includes(parsed.pathname)
    || !CAPABILITY_FRAGMENT.test(parsed.hash)
  ) {
    throw new Error("Gate09 launch URL is not a constrained loopback capability URL.");
  }
  return parsed;
}

function validatedReportPath(): string {
  const value = requiredEnvironment("BLUEFIRE_BROWSER_REPORT_PATH");
  if (!isAbsolute(value) || !value.toLowerCase().endsWith(".json")) {
    throw new Error("Gate09 browser report path must be an absolute JSON path.");
  }
  return value;
}

function dataValue(parent: Locator, label: string): Locator {
  return parent.locator("dt", { hasText: new RegExp(`^${label}$`) })
    .locator("..")
    .locator("dd")
    .first();
}

function normalized(value: string): string {
  return value.trim().toLowerCase().replaceAll(" ", "_");
}

async function writeExclusiveReport(path: string, report: Record<string, unknown>): Promise<void> {
  let handle: Awaited<ReturnType<typeof fs.open>> | undefined;
  try {
    handle = await fs.open(path, "wx", 0o600);
    await handle.writeFile(`${JSON.stringify(report, null, 2)}\n`, "utf8");
    await handle.sync();
  } catch {
    if (handle) {
      await handle.close();
      handle = undefined;
    }
    throw new Error("Gate09 browser report could not be created exclusively.");
  } finally {
    await handle?.close();
  }
}

function installFailureMonitors(page: Page): { assertClean: () => void } {
  const failures: string[] = [];
  const chromiumBootstrapAborts = { GET: 0, POST: 0 };
  page.on("console", (message) => {
    if (message.type() === "error") failures.push("console_error");
  });
  page.on("pageerror", () => failures.push("page_error"));
  page.on("requestfailed", (request) => {
    const path = new URL(request.url()).pathname;
    const error = request.failure()?.errorText ?? "unknown";
    const method = request.method();
    if (
      (method === "POST" || method === "GET")
      && path === "/api/v1/session"
      && request.resourceType() === "fetch"
      && error === "net::ERR_ABORTED"
    ) {
      chromiumBootstrapAborts[method] += 1;
      if (chromiumBootstrapAborts[method] > 1) {
        failures.push(`repeated_${method.toLowerCase()}_session_transport_abort`);
      }
      return;
    }
    failures.push(`network_request_failed:${request.method()}:${path}:${error}`);
  });
  page.on("response", (response) => {
    if (response.status() >= 400) {
      failures.push(`http_error_response:${response.status()}:${new URL(response.url()).pathname}`);
    }
  });
  return {
    assertClean: () => {
      expect(failures, "The production browser emitted a console, page, or network failure.").toEqual([]);
    },
  };
}

test("production UI exposes pinned intake provenance and its active behavior", async ({ page }) => {
  const launchUrl = validatedLaunchUrl();
  const reportPath = validatedReportPath();
  const profileId = requiredEnvironment("BLUEFIRE_GATE09_PROFILE_ID");
  const expectedRecordSha256 = requiredEnvironment("BLUEFIRE_GATE09_EXPECTED_RECORD_SHA256");
  expect(expectedRecordSha256).toMatch(/^sha256:[0-9a-f]{64}$/);
  expect(await fs.access(reportPath).then(() => true, () => false)).toBe(false);

  const monitoring = installFailureMonitors(page);
  const completedOperations: string[] = [];
  await page.goto(launchUrl.href, { waitUntil: "domcontentloaded" });
  const navigation = page.getByRole("navigation", { name: "Primary navigation" });
  await expect(navigation).toBeVisible();
  await expect.poll(() => page.url()).not.toContain("bluefire-session=");
  completedOperations.push("bootstrap_production_session");
  monitoring.assertClean();

  await navigation.getByRole("link", { name: "Research Sources" }).click();
  await expect(page.getByRole("heading", { name: "Research sources", level: 1 })).toBeVisible();
  await expect(page.getByText("Immutable references, no blind imports")).toBeVisible();
  completedOperations.push("open_research_sources");

  const sourceCard = page.locator(".source-card").filter({ hasText: SOURCE_PROJECT }).first();
  await expect(sourceCard).toBeVisible();
  await expect(dataValue(sourceCard, "Project")).toHaveText(SOURCE_PROJECT);
  await expect(dataValue(sourceCard, "Version")).toHaveText(SOURCE_VERSION);
  await expect(dataValue(sourceCard, "Immutable pin").locator("code")).toHaveAttribute("title", SOURCE_PIN);
  await expect(dataValue(sourceCard, "License")).toContainText(SOURCE_LICENSE);
  await expect(dataValue(sourceCard, "Relationship")).toHaveText("Imported");
  await expect(dataValue(sourceCard, "Use classification")).toHaveText("Metadata import");
  await expect(dataValue(sourceCard, "Content handling")).toHaveText("Vendored declarative");
  await expect(dataValue(sourceCard, "Executable content")).toHaveText("No");
  await expect(dataValue(sourceCard, "License review")).toHaveText("Reviewed");
  completedOperations.push("verify_pinned_source");

  await sourceCard.locator("summary", { hasText: "Intake review" }).click();
  await expect(dataValue(sourceCard, "Source ID")).toHaveText(SOURCE_ID);
  await expect(dataValue(sourceCard, "Exact ref")).toHaveText(SOURCE_PIN);
  await expect(dataValue(sourceCard, "Imported/adapted paths")).toContainText(SOURCE_PATH);
  await expect(dataValue(sourceCard, "Imported/adapted paths")).toContainText(LICENSE_PATH);
  await expect(dataValue(sourceCard, "Attribution")).toContainText(REQUIRED_NOTICE);
  await expect(dataValue(sourceCard, "Security review")).toContainText(/not executed|never executed/i);
  await expect(sourceCard.locator("details > p")).toContainText(/projection|transform/i);
  completedOperations.push("expand_intake_review");
  monitoring.assertClean();

  await page.getByLabel("Reviewed intake destination ID").fill(INTAKE_DESTINATION_ID);
  await page.getByLabel("Reviewed intake runner profile").selectOption(profileId);
  await page.getByLabel("Reviewed intake operator ID").fill(INTAKE_OPERATOR_ID);
  completedOperations.push("configure_reviewed_intake");
  await page.getByRole("button", { name: "Import and activate reviewed T1082" }).click();
  const intakeResult = page.getByTestId("reviewed-intake-result");
  await expect(intakeResult).toBeVisible();
  await expect(dataValue(intakeResult, "Destination")).toHaveText(INTAKE_DESTINATION_ID);
  await expect(dataValue(intakeResult, "Intake record")).toHaveText(expectedRecordSha256);
  await expect(dataValue(intakeResult, "Durable state")).toHaveText(`source-intakes/${INTAKE_DESTINATION_ID}/${INTAKE_ID}.json`);
  await expect(dataValue(intakeResult, "Receipt state")).toHaveText(`source-intakes/${INTAKE_DESTINATION_ID}/${INTAKE_ID}.operation-receipt.json`);
  await expect(dataValue(intakeResult, "Receipt SHA-256")).toHaveText(SHA256);
  const operationReceiptSha256 = (await dataValue(intakeResult, "Receipt SHA-256").textContent() ?? "").trim();
  await expect(dataValue(intakeResult, "Activation")).toHaveText("Already active revalidated");
  await expect(dataValue(intakeResult, "Behavior")).toHaveText(BEHAVIOR_ID);
  await expect(dataValue(intakeResult, "Action")).toHaveText(ACTION_ID);
  await expect(dataValue(intakeResult, "Runner profile")).toHaveText(profileId);
  completedOperations.push("activate_reviewed_intake");
  monitoring.assertClean();

  await navigation.getByRole("link", { name: "Behaviors" }).click();
  await expect(page.getByRole("heading", { name: "Neutral, typed behavior contracts", level: 1 })).toBeVisible();
  completedOperations.push("open_behaviors");
  await page.getByLabel("Search behaviors").fill(BEHAVIOR_ID);
  const behaviorRow = page.getByRole("listitem").filter({ hasText: BEHAVIOR_ID }).first();
  await expect(behaviorRow).toBeVisible();
  await behaviorRow.click();
  const detail = page.locator(".detail-panel");
  await expect(dataValue(detail, "Behavior ID")).toHaveText(BEHAVIOR_ID);
  await expect(dataValue(detail, "Techniques")).toHaveText("T1082");
  await expect(dataValue(detail, "Actions")).toHaveText(ACTION_ID);
  await expect(detail.locator(".panel-header")).toContainText("System Information Discovery");
  await expect(behaviorRow).toContainText("Action");
  completedOperations.push("verify_imported_behavior");
  const provenanceReference = `urn:bluefire:source-intake:${INTAKE_ID}:sha256:${expectedRecordSha256.slice("sha256:".length)}`;
  await expect(dataValue(detail, "Source")).toHaveText("Reviewed MITRE ATT&CK® v19.2 T1082 intake");
  await expect(dataValue(detail, "Source reference")).toHaveText(provenanceReference);
  await expect(dataValue(detail, "Source license")).toHaveText(SOURCE_LICENSE);
  await expect(dataValue(detail, "Relationship")).toContainText("Neutral metadata projection");
  completedOperations.push("verify_behavior_provenance");
  monitoring.assertClean();

  await page.reload({ waitUntil: "domcontentloaded" });
  await expect(page.getByRole("heading", { name: "Neutral, typed behavior contracts", level: 1 })).toBeVisible();
  await page.getByLabel("Search behaviors").fill(BEHAVIOR_ID);
  await expect(page.getByRole("listitem").filter({ hasText: BEHAVIOR_ID }).first()).toBeVisible();
  await navigation.getByRole("link", { name: "Research Sources" }).click();
  const persistedSource = page.locator(".source-card").filter({ hasText: SOURCE_PROJECT }).first();
  await expect(dataValue(persistedSource, "Immutable pin").locator("code")).toHaveAttribute("title", SOURCE_PIN);
  completedOperations.push("reload_and_verify_persisted_state");
  expect(completedOperations).toEqual(OPERATION_SEQUENCE);
  monitoring.assertClean();

  await writeExclusiveReport(reportPath, {
    schema_version: "bluefire.source-intake-production-browser.v1",
    production_browser_interaction: true,
    demo_mode: false,
    origin: launchUrl.origin,
    source_id: SOURCE_ID,
    source_project: SOURCE_PROJECT,
    source_version: SOURCE_VERSION,
    source_pin: SOURCE_PIN,
    source_license: SOURCE_LICENSE,
    source_classification: SOURCE_CLASSIFICATION,
    source_content_handling: SOURCE_CONTENT_HANDLING,
    imported_paths: [SOURCE_PATH, LICENSE_PATH],
    attribution_visible: true,
    transformation_visible: true,
    behavior_id: BEHAVIOR_ID,
    technique_id: "T1082",
    action_id: ACTION_ID,
    activation_operation: "already_active_revalidated",
    behavior_provenance_reference: provenanceReference,
    behavior_provenance_visible: true,
    execution_state: normalized("Action"),
    intake_destination_id: INTAKE_DESTINATION_ID,
    intake_record_sha256: expectedRecordSha256,
    intake_state_ref: `source-intakes/${INTAKE_DESTINATION_ID}/${INTAKE_ID}.json`,
    operation_receipt_visible: true,
    operation_receipt_sha256: operationReceiptSha256,
    operation_receipt_state_ref: `source-intakes/${INTAKE_DESTINATION_ID}/${INTAKE_ID}.operation-receipt.json`,
    operation_sequence: completedOperations,
    runner_profile_id: profileId,
    observed_at: new Date().toISOString(),
  });
});
