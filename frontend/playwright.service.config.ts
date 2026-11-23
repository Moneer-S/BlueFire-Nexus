import { defineConfig, devices } from "@playwright/test";

// The real thing: the Python service serving the committed interface in
// bluefire/ui, with no demo data. One worker, because the service hands its
// one-time connection code to one browser.
export default defineConfig({
  testDir: "./tests/service",
  globalSetup: "./tests/service/start-service.ts",
  timeout: 60_000,
  workers: 1,
  retries: 0,
  reporter: "list",
  use: {
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
});
