import { existsSync, lstatSync } from "node:fs";
import { isAbsolute } from "node:path";
import { URL } from "node:url";
import process from "node:process";
import { defineConfig, devices } from "@playwright/test";

const CAPABILITY_FRAGMENT = /^#bluefire-session=[A-Za-z0-9_-]{64}$/;
const LOOPBACK_HOSTS = new Set(["127.0.0.1", "[::1]", "::1"]);

function requiredEnvironment(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`Gate07 browser configuration is missing ${name}.`);
  return value;
}

function productionLaunchUrl(): URL {
  let parsed: URL;
  try {
    parsed = new URL(requiredEnvironment("BLUEFIRE_PRODUCTION_URL"));
  } catch {
    throw new Error("Gate07 requires one valid production loopback launch URL.");
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
    throw new Error("Gate07 requires an HTTP loopback launch URL with one valid browser capability fragment.");
  }
  return parsed;
}

function newAbsolutePath(name: string): string {
  const value = requiredEnvironment(name);
  if (!isAbsolute(value)) throw new Error(`${name} must be an absolute path.`);
  if (existsSync(value)) throw new Error(`${name} must not collide with an existing path.`);
  return value;
}

function absoluteOutputDirectory(name: string): string {
  const value = requiredEnvironment(name);
  if (!isAbsolute(value)) throw new Error(`${name} must be an absolute path.`);
  if (existsSync(value)) {
    const entry = lstatSync(value);
    if (!entry.isDirectory() || entry.isSymbolicLink()) {
      throw new Error(`${name} must be a regular directory when present.`);
    }
  }
  return value;
}

productionLaunchUrl();
newAbsolutePath("BLUEFIRE_BROWSER_REPORT_PATH");
const artifactDirectory = absoluteOutputDirectory("BLUEFIRE_BROWSER_ARTIFACT_DIR");
if (process.env.VITE_DEMO_MODE === "true") {
  throw new Error("Gate07 production browser evidence cannot run with demo mode enabled.");
}

export default defineConfig({
  testDir: "./tests/e2e",
  testMatch: "detection-production.spec.ts",
  timeout: 90_000,
  expect: { timeout: 12_000 },
  fullyParallel: false,
  workers: 1,
  retries: 0,
  forbidOnly: true,
  reporter: "list",
  outputDir: artifactDirectory,
  use: {
    baseURL: productionLaunchUrl().origin,
    actionTimeout: 12_000,
    navigationTimeout: 20_000,
    acceptDownloads: false,
    ignoreHTTPSErrors: false,
    serviceWorkers: "block",
    trace: "off",
    screenshot: "off",
    video: "off",
  },
  projects: [
    { name: "chromium", use: { ...devices["Desktop Chrome"] } },
  ],
});
