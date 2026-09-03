import { promises as fs } from "node:fs";
import { isAbsolute } from "node:path";
import process from "node:process";
import { randomUUID } from "node:crypto";
import { URL } from "node:url";
import { expect, test, type Locator, type Page } from "@playwright/test";

const CAPABILITY_FRAGMENT = /^#bluefire-session=[A-Za-z0-9_-]{64}$/;
const LOOPBACK_HOSTS = new Set(["127.0.0.1", "[::1]", "::1"]);
const CANDIDATE_ID = /^detection-[0-9a-f]{20}$/;
const SHA256 = /^sha256:[0-9a-f]{64}$/;
const OPERATION_SEQUENCE = [
  "bootstrap_production_session",
  "open_detection_lab",
  "verify_sqlite_backend",
  "create_sqlite_hypothesis",
  "parse_sqlite_query",
  "execute_malicious_fixture",
  "reload_and_verify_persisted_state",
] as const;

function requiredEnvironment(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`Gate07 browser test is missing ${name}.`);
  return value;
}

function validatedLaunchUrl(): URL {
  let parsed: URL;
  try {
    parsed = new URL(requiredEnvironment("BLUEFIRE_PRODUCTION_URL"));
  } catch {
    throw new Error("Gate07 production launch URL is invalid.");
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
    throw new Error("Gate07 production launch URL is not a constrained loopback capability URL.");
  }
  return parsed;
}

function validatedReportPath(): string {
  const value = requiredEnvironment("BLUEFIRE_BROWSER_REPORT_PATH");
  if (!isAbsolute(value) || !value.toLowerCase().endsWith(".json")) {
    throw new Error("Gate07 browser report path must be an absolute JSON path.");
  }
  return value;
}

function dataValue(workspace: Locator, label: string): Locator {
  return workspace.locator("dt", { hasText: new RegExp(`^${label}$`) })
    .locator("..")
    .locator("dd")
    .first();
}

function normalizedState(value: string): string {
  return value.trim().toLowerCase().replaceAll(" ", "_");
}

function splitBackend(value: string): { name: string; version: string } {
  const parts = value.split("·").map((item) => item.trim()).filter(Boolean);
  if (parts.length !== 2 || !parts[0] || !parts[1]) {
    throw new Error("The production UI did not expose a backend name and version.");
  }
  return { name: parts[0], version: parts[1] };
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
    throw new Error("Gate07 browser report could not be created exclusively.");
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
    // Chromium classifies the successful empty 204 session probes as ERR_ABORTED.
    // Permit at most one POST bootstrap and one GET reload probe; the protected UI
    // and subsequent authenticated API reads still have to render successfully.
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

test("production Detection Lab executes and persists a native SQLite candidate", async ({ page }) => {
  const launchUrl = validatedLaunchUrl();
  const reportPath = validatedReportPath();
  expect(
    await fs.access(reportPath).then(() => true, () => false),
    "Browser report output already exists.",
  ).toBe(false);

  const monitoring = installFailureMonitors(page);
  const completedOperations: string[] = [];
  const title = `Gate07 production SQLite ${randomUUID().replaceAll("-", "").slice(0, 12)}`;
  const fixtureId = `gate07-browser-${randomUUID().replaceAll("-", "").slice(0, 16)}`;
  const query = "SELECT * FROM logs WHERE artifact_type = 'file_observation' AND path LIKE '%staged/%'";

  await page.goto(launchUrl.href, { waitUntil: "domcontentloaded" });
  const navigation = page.getByRole("navigation", { name: "Primary navigation" });
  await expect(navigation).toBeVisible();
  await expect.poll(() => page.url()).not.toContain("bluefire-session=");
  completedOperations.push("bootstrap_production_session");
  monitoring.assertClean();

  await navigation.getByRole("link", { name: "Detection Lab" }).click();
  await expect(page.getByRole("heading", { name: "Detection Lab", level: 1 })).toBeVisible();
  await expect(page.getByText("Rendered text is not validation.")).toBeVisible();
  await expect(page.getByText(/Demo mode previews|Seeded review|Demo candidates do not run/)).toHaveCount(0);
  completedOperations.push("open_detection_lab");
  monitoring.assertClean();

  const sqliteHealth = page.locator("article.secret-row").filter({
    has: page.getByText("Sqlite", { exact: true }),
  }).first();
  await expect(sqliteHealth).toBeVisible();
  await expect(sqliteHealth).toContainText("SQLite bounded executor");
  await expect(sqliteHealth.getByText("Ready", { exact: true })).toBeVisible();
  await expect(sqliteHealth.getByText("Authoritative", { exact: true })).toBeVisible();
  completedOperations.push("verify_sqlite_backend");
  monitoring.assertClean();

  await page.getByLabel("Title", { exact: true }).fill(title);
  await page.getByLabel("Target language").selectOption("sqlite");
  await page.getByRole("button", { name: "Save strict hypothesis" }).click();
  await expect(page.getByText(/saved as a strict hypothesis\. It has not been parsed or exercised\./)).toBeVisible();
  const workspace = page.locator("section.candidate-workspace");
  await expect(workspace.getByRole("heading", { name: title })).toBeVisible();
  const candidateId = (await dataValue(workspace, "Candidate ID").innerText()).trim();
  expect(candidateId).toMatch(CANDIDATE_ID);
  await expect(workspace.locator(".panel-header .badge")).toHaveText("Hypothesis");
  completedOperations.push("create_sqlite_hypothesis");
  monitoring.assertClean();

  await workspace.getByLabel(/Sqlite source/i).fill(query);
  await workspace.getByRole("button", { name: "Parse / compile honestly" }).click();
  await expect(page.getByText(new RegExp(`${candidateId} advanced honestly to parsed\\.`, "i"))).toBeVisible();
  await expect(workspace.locator(".panel-header .badge")).toHaveText("Parsed");
  await expect(dataValue(workspace, "Converted query digest")).toHaveText(SHA256);
  await expect(dataValue(workspace, "Source query executed")).toHaveText("No");
  completedOperations.push("parse_sqlite_query");
  monitoring.assertClean();

  await workspace.getByRole("tab", { name: "Fixtures" }).click();
  await workspace.getByLabel("Malicious fixtures JSON").fill(JSON.stringify([{
    fixture_id: fixtureId,
    artifact_type: "file_observation",
    path: "staged/browser-proof.txt",
  }]));
  await workspace.getByRole("button", { name: "Exercise malicious fixtures" }).click();
  await expect(page.getByText(new RegExp(`${candidateId} advanced honestly to fixture exercised\\.`, "i"))).toBeVisible();
  await expect(workspace.locator(".panel-header .badge")).toHaveText("Fixture exercised");
  await expect(workspace.getByText("1 retained", { exact: true })).toBeVisible();
  completedOperations.push("execute_malicious_fixture");
  monitoring.assertClean();

  await page.reload({ waitUntil: "domcontentloaded" });
  await expect(page.getByRole("heading", { name: "Detection Lab", level: 1 })).toBeVisible();
  await page.getByLabel("Search detection candidates").fill(title);
  await expect(page.locator("section.candidate-workspace").getByRole("heading", { name: title })).toBeVisible();
  const persistedWorkspace = page.locator("section.candidate-workspace");
  await persistedWorkspace.getByRole("tab", { name: "Candidate" }).click();
  await expect(dataValue(persistedWorkspace, "Candidate ID")).toHaveText(candidateId);
  const visibleState = normalizedState(await persistedWorkspace.locator(".panel-header .badge").innerText());
  expect(visibleState).toBe("fixture_exercised");
  const queryDigest = (await dataValue(persistedWorkspace, "Converted query digest").innerText()).trim();
  expect(queryDigest).toMatch(SHA256);
  await expect(dataValue(persistedWorkspace, "Source query executed")).toHaveText("Yes");
  await expect(dataValue(persistedWorkspace, "Evaluated records")).toHaveText(fixtureId);
  await expect(dataValue(persistedWorkspace, "Matched records")).toHaveText(fixtureId);
  const parserName = (await dataValue(persistedWorkspace, "Parser").innerText()).trim();
  const parserVersion = (await dataValue(persistedWorkspace, "Parser version").innerText()).trim();
  const execution = splitBackend(await dataValue(persistedWorkspace, "Execution backend").innerText());
  expect(parserName).toBe("SQLite bounded executor");
  expect(parserVersion).not.toBe("Not reported");
  expect(execution.name).toBe("SQLite in-memory bounded executor");
  completedOperations.push("reload_and_verify_persisted_state");
  expect(completedOperations).toEqual(OPERATION_SEQUENCE);
  monitoring.assertClean();

  await writeExclusiveReport(reportPath, {
    schema_version: "bluefire.detection-production-browser.v1",
    production_browser_interaction: true,
    demo_mode: false,
    origin: launchUrl.origin,
    candidate_id: candidateId,
    visible_state: visibleState,
    query_digest: queryDigest,
    backend: {
      parser: parserName,
      parser_version: parserVersion,
      execution: execution.name,
      execution_version: execution.version,
    },
    evaluated_fixture_ids: [fixtureId],
    matched_fixture_ids: [fixtureId],
    operation_sequence: completedOperations,
    observed_at: new Date().toISOString(),
  });
});
