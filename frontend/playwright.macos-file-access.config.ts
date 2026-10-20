import { defineConfig } from "@playwright/test";
import base from "./playwright.ad-smb-workspace.config";

export default defineConfig({ ...base, testMatch: "macos-file-access-production.spec.ts" });
