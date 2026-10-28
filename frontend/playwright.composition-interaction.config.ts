import { defineConfig } from "@playwright/test";
import base from "./playwright.ad-smb-workspace.config";

export default defineConfig({ ...base, testMatch: "composition-interaction-production.spec.ts", use: { ...base.use, viewport: { width: 1440, height: 900 } } });
