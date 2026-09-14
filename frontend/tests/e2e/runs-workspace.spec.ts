import { expect, test } from "@playwright/test";

test("Runs fits laptop and narrow screens while idle history stays ahead of live controls", async ({ page }) => {
  await page.setViewportSize({ width: 1366, height: 768 });
  await page.goto("./#/runs");
  await expect(page.getByRole("heading", { name: "Run history" })).toBeVisible();
  await expect(page.locator(".live-console")).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Run preflight", exact: true })).toHaveCount(0);
  await page.getByRole("link", { name: "Review new run", exact: true }).click();
  await expect(page.getByRole("button", { name: "Run preflight", exact: true })).toHaveCount(1);
  await page.getByRole("radio", { name: /Execute/ }).check();
  await expect(page.locator('[aria-current="step"]')).toHaveCount(1);
  await expect(page.getByRole("button", { name: "Run preflight", exact: true })).toHaveCount(1);
  await expect(page.getByRole("button", { name: "Create approval-gated job" })).toBeDisabled();
  for (const width of [1366, 390]) {
    await page.setViewportSize({ width, height: 844 });
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(width);
    await expect(page.getByRole("combobox", { name: "Environment profile" })).toBeVisible();
    await expect(page.getByRole("group", { name: "Requested access" })).toBeVisible();
    await expect(page.getByRole("checkbox", { name: "Files in the selected workspace" })).toBeVisible();
  }
  await expect(page.getByRole("textbox", { name: "Target scope" })).toBeHidden();
  await page.getByText("Environment and scope references", { exact: true }).click();
  await expect(page.getByRole("textbox", { name: "Target scope" })).toBeVisible();
  await page.getByRole("radio", { name: /^Simulate/ }).check();
  await expect(page.getByRole("region", { name: "Guided local Execute" })).toHaveCount(0);
  await expect(page.locator(".live-console")).toHaveCount(0);
  await page.getByRole("button", { name: "Run preflight", exact: true }).click();
  await page.getByRole("button", { name: "Submit Simulate job" }).click();
  await expect(page.locator(".live-console")).toBeVisible();
  await expect(page.locator(".live-console").getByRole("button", { name: "Review", exact: true })).toBeEnabled();
  const result = page.getByRole("link", { name: "Review latest result", exact: true });
  await expect(result).toHaveAttribute("href", "#/runs/demo-simulate-baseline");
  await result.click();
  await expect(page).toHaveURL(/#\/runs\/demo-simulate-baseline$/);
});
