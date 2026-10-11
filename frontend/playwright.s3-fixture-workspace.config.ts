import { defineConfig } from "@playwright/test";
import reviewed from "./playwright.s3-workspace.config";

export default defineConfig({
  ...reviewed,
  testMatch: "s3-fixture-workspace-production.spec.ts",
});
