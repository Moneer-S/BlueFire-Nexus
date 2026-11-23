import { expect, test } from "@playwright/test";

// The demo build's tests never reach the service. This one opens the address
// the real service prints and walks the main screens it serves.
test("the service serves the interface, and its main screens open on a fresh workspace", async ({ page }) => {
  const problems: string[] = [];
  page.on("pageerror", error => problems.push(String(error)));
  page.on("response", response => {
    if (response.status() >= 500) problems.push(`${response.status()} ${response.url()}`);
  });

  await page.goto(process.env.BLUEFIRE_SERVICE_URL ?? "");
  await expect(page.getByRole("heading", { name: "Overview", exact: true })).toBeVisible();
  await expect(page.getByText("Connected", { exact: true })).toBeVisible();

  // What a fresh workspace holds: the packaged experiments, and no runs yet.
  await page.getByRole("link", { name: "Experiments", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Experiments", exact: true })).toBeVisible();
  await expect(page.getByText("Collect samples with a local fallback").first()).toBeVisible();

  await page.getByRole("link", { name: "Build", exact: true }).click();
  await expect(page.getByRole("button", { name: "Validate", exact: true })).toBeVisible();

  await page.getByRole("link", { name: "Runs", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Runs", exact: true })).toBeVisible();
  await expect(page.getByText("No runs yet.")).toBeVisible();

  await page.getByRole("link", { name: "Detection Lab", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Detection Lab", exact: true })).toBeVisible();

  await page.getByRole("link", { name: "Compare", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Compare runs", exact: true })).toBeVisible();

  expect(problems).toEqual([]);
});
