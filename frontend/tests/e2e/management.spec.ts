import { expect, test } from "@playwright/test";

test("Detection Lab creates an honest hypothesis without simulating validation", async ({ page }) => {
  const consoleErrors: string[] = [];
  page.on("console", (message) => { if (message.type() === "error") consoleErrors.push(message.text()); });
  await page.goto("./#/detection-lab");
  await expect(page.getByRole("heading", { name: "Detection Lab" })).toBeVisible();
  await expect(page.getByText("Rendered text is not validation.")).toBeVisible();

  await page.getByRole("button", { name: "Save strict hypothesis" }).click();
  await expect(page.getByText(/saved as a strict hypothesis\. It has not been parsed or exercised\./)).toBeVisible();
  await expect(page.getByRole("button", { name: "Parse / compile honestly" })).toBeEnabled();

  await page.getByRole("button", { name: "Parse / compile honestly" }).click();
  await expect(page.getByText(/Demo candidates do not run parser, fixture, evidence, or rejection lifecycle actions\./)).toBeVisible();
  expect(consoleErrors).toEqual([]);
});

test("legacy plugin manifests remain provenance-only while activation moves to signed packages", async ({ page }) => {
  await page.goto("./#/actions");
  await expect(page.getByRole("heading", { name: "Actions & plugins" })).toBeVisible();
  await page.getByRole("button", { name: "Add manifest" }).click();
  await page.getByLabel("Reviewed SHA-256").fill("a".repeat(64));
  await page.getByLabel("Trust review").selectOption("reviewed");
  await page.getByRole("checkbox", { name: "Declaratively eligible" }).check();
  await page.getByRole("button", { name: "Save strict manifest" }).click();

  await expect(page.getByText(/plugin\.local-review\.v1 manifest saved as ready\. No package was downloaded or installed\./)).toBeVisible();
  await expect(page.getByRole("button", { name: "Activate metadata" })).toHaveCount(0);
  await expect(page.getByText("Legacy metadata lifecycle retired")).toBeVisible();
  await expect(
    page.getByLabel("Primary navigation").getByRole("link", { name: "Action Packages" }),
  ).toHaveAttribute("href", "#/action-packages");
  const legacyManifest = page.locator("article").filter({ hasText: "plugin.local-review.v1" });
  await expect(legacyManifest).toContainText("Provenance only");
  await expect(
    page.getByText("Executable loading", { exact: true }).locator("..").getByText("Disabled", { exact: true }),
  ).toBeVisible();
});
