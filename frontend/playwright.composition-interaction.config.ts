import { defineConfig } from "@playwright/test";
import base from "./playwright.ad-smb-workspace.config";

export default defineConfig({ ...base, testMatch: "composition-interaction-production.spec.ts", projects: [
  { name: "1366x768", grepInvert: /constrained desktop/, use: { viewport: { width: 1366, height: 768 } } },
  { name: "1440x900", grepInvert: /constrained desktop/, use: { viewport: { width: 1440, height: 900 } } },
  { name: "1920x1080", grepInvert: /constrained desktop/, use: { viewport: { width: 1920, height: 1080 } } },
  { name: "1000x800", grep: /constrained desktop/, use: { viewport: { width: 1000, height: 800 } } },
] });
