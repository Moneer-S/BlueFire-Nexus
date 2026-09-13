import { readFile } from "node:fs/promises";
import { expect, test } from "@playwright/test";

test("saved run review downloads a readable report and identifies the demo bundle boundary", async ({ page }, testInfo) => {
  await page.setViewportSize({ width: 1366, height: 768 });
  await page.goto("./#/runs/demo-simulate-baseline");
  await expect(page.getByRole("button", { name: "Download report" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Download run bundle" })).toBeDisabled();
  const waiting = page.waitForEvent("download");
  await page.getByRole("button", { name: "Download report" }).click();
  const download = await waiting;
  expect(download.suggestedFilename()).toBe("demo-simulate-baseline.md");
  const path = await download.path();
  expect(path).toBeTruthy();
  const report = await readFile(path!, "utf8");
  expect(report).toContain("BlueFire run report");
  expect(report).toContain("sanitized demo");
  expect(report).toContain("Simulation does not establish real effects");
  expect(report).toContain("Detector revisions and Detection Lab evaluations are separate records");
  await page.screenshot({ path: testInfo.outputPath("run-review-export.png") });
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(1366);
});
