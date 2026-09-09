import { expect, test } from "@playwright/test";

test("Assistant stays reachable on laptop and narrow screens and returns keyboard focus", async ({ page }) => {
  await page.goto("./#/detection-lab");
  for (const width of [1280, 390, 320]) {
    await page.setViewportSize({ width, height: 844 });
    const trigger = page.getByRole("button", { name: /^Assistant$/ });
    await expect(trigger).toBeVisible();
    await trigger.click();
    const dialog = page.getByRole("complementary", { name: "Experiment assistant" });
    await expect(dialog).toBeVisible();
    await expect(dialog.getByText(/This preview cannot run assistant operations/)).toBeVisible();
    await expect(dialog.getByRole("button", { name: "Start work" })).toBeDisabled();
    expect(await dialog.evaluate((element) => element.scrollWidth)).toBeLessThanOrEqual(width);
    await expect(page.getByRole("main")).not.toHaveAttribute("inert");
    await dialog.getByRole("button", { name: "Close assistant" }).focus();
    await page.keyboard.press("Escape");
    await expect(dialog).toHaveCount(0);
    await expect(trigger).toBeFocused();
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(width);
  }
});
