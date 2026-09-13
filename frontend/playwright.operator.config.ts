import { existsSync, lstatSync } from "node:fs";
import { isAbsolute } from "node:path";
import process from "node:process";
import { URL } from "node:url";
import { defineConfig, devices } from "@playwright/test";

const CAPABILITY_FRAGMENT = /^#bluefire-session=[A-Za-z0-9_-]{64}$/;
const LOOPBACK_HOSTS = new Set(["127.0.0.1", "[::1]", "::1"]);
const RUN_ID = /^run-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{16}$/;

function requiredEnvironment(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`Gate08 browser configuration is missing ${name}.`);
  return value;
}

function productionLaunchUrl(): URL {
  let parsed: URL;
  try {
    parsed = new URL(requiredEnvironment("BLUEFIRE_PRODUCTION_URL"));
  } catch {
    throw new Error("Gate08 requires one valid production loopback launch URL.");
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
    throw new Error("Gate08 requires an HTTP loopback URL with one browser capability fragment.");
  }
  return parsed;
}

function newAbsolutePath(name: string): string {
  const value = requiredEnvironment(name);
  if (!isAbsolute(value) || existsSync(value)) {
    throw new Error(`${name} must be a new absolute path.`);
  }
  return value;
}

function existingAbsoluteDirectory(name: string): string {
  const value = requiredEnvironment(name);
  if (!isAbsolute(value) || !existsSync(value)) {
    throw new Error(`${name} must be an existing absolute directory.`);
  }
  const entry = lstatSync(value);
  if (!entry.isDirectory() || entry.isSymbolicLink()) {
    throw new Error(`${name} must be a regular directory.`);
  }
  return value;
}

productionLaunchUrl();
newAbsolutePath("BLUEFIRE_BROWSER_REPORT_PATH");
existingAbsoluteDirectory("BLUEFIRE_BROWSER_SCREENSHOT_DIR");
existingAbsoluteDirectory("BLUEFIRE_BROWSER_ARTIFACT_DIR");
if (!RUN_ID.test(requiredEnvironment("BLUEFIRE_BASELINE_RUN_ID"))) {
  throw new Error("Gate08 baseline run ID is invalid.");
}
if (process.env.VITE_DEMO_MODE === "true") {
  throw new Error("Gate08 production browser evidence cannot run in demo mode.");
}

export default defineConfig({
  testDir: "./tests/e2e",
  testMatch: "operator-production.spec.ts",
  timeout: 180_000,
  expect: { timeout: 15_000 },
  fullyParallel: false,
  workers: 1,
  retries: 0,
  forbidOnly: true,
  reporter: "list",
  outputDir: requiredEnvironment("BLUEFIRE_BROWSER_ARTIFACT_DIR"),
  use: {
    baseURL: productionLaunchUrl().origin,
    viewport: { width: 1600, height: 1000 },
    actionTimeout: 15_000,
    navigationTimeout: 25_000,
    acceptDownloads: true,
    ignoreHTTPSErrors: false,
    serviceWorkers: "block",
    trace: "off",
    screenshot: "off",
    video: "off",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"], viewport: { width: 1600, height: 1000 } } }],
});
