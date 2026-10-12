import { defineConfig } from "@playwright/test";
import base from "./playwright.s3-workspace.config";

export default defineConfig({ ...base, testMatch: "s3-audit-production.spec.ts" });
