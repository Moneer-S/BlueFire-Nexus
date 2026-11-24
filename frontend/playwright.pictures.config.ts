import { defineConfig, devices } from "@playwright/test";

// Not a test: the script that takes the pictures of the live view and keeps the
// replay page, against the real service (see tests/pictures/live-view.ts).
export default defineConfig({
  testDir: "./tests/pictures",
  testMatch: "live-view.ts",
  globalSetup: "./tests/service/start-service.ts",
  // The loop opens the page once for each of its frames.
  timeout: 600_000,
  workers: 1,
  retries: 0,
  reporter: "list",
  outputDir: "./test-results/pictures",
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"], deviceScaleFactor: 1, colorScheme: "dark" } }],
});
