import { defineConfig } from "@playwright/test";
import base from "./playwright.s3-workspace.config";

export default defineConfig({ ...base, testMatch: "audit-assistance-production.spec.ts" });
