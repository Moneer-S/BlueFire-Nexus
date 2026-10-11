import { existsSync, lstatSync } from "node:fs";
import { isAbsolute, join } from "node:path";
import { defineConfig } from "@playwright/test";

function directory(name: string): string {
  const value = process.env[name];
  if (!value || !isAbsolute(value) || !existsSync(value) || !lstatSync(value).isDirectory() || lstatSync(value).isSymbolicLink()) {
    throw new Error("The synthetic S3 browser check requires explicit regular directories.");
  }
  return value;
}
const output = directory("BLUEFIRE_S3_BROWSER_OUTPUT");
directory("BLUEFIRE_S3_BROWSER_BUNDLE");
const browser = process.env.BLUEFIRE_S3_BROWSER_EXECUTABLE;
const port = process.env.BLUEFIRE_S3_BROWSER_PORT;
if (!browser || !isAbsolute(browser) || !lstatSync(browser).isFile() || !/^\d{4,5}$/.test(port ?? "") || Number(port) > 65535 || process.env.VITE_DEMO_MODE !== "false") {
  throw new Error("The synthetic S3 browser runtime was not explicitly selected.");
}
if (existsSync(join(output, "playwright.json"))) throw new Error("The synthetic S3 browser report already exists.");

export default defineConfig({
  testDir: "./tests/e2e",
  testMatch: "s3-workspace-production.spec.ts",
  globalSetup: "./tests/s3-browser-setup.ts",
  timeout: 90_000,
  globalTimeout: 240_000,
  expect: { timeout: 10_000 },
  fullyParallel: false,
  workers: 1,
  retries: 0,
  forbidOnly: true,
  reporter: [["json", { outputFile: join(output, "playwright.json") }]],
  outputDir: join(output, "test-artifacts"),
  use: {
    baseURL: `http://127.0.0.1:${port}/ui/`,
    browserName: "chromium",
    launchOptions: {
      executablePath: browser,
      args: ["--host-resolver-rules=MAP * 0.0.0.0, EXCLUDE 127.0.0.1", "--no-proxy-server", "--disable-background-networking"],
    },
    serviceWorkers: "block",
    acceptDownloads: false,
    viewport: { width: 1366, height: 900 },
    actionTimeout: 10_000,
    navigationTimeout: 15_000,
    trace: "off",
    screenshot: "off",
    video: "off",
  },
});
