import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes, useLocation } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { AppShell } from "../src/components/AppShell";
import { api } from "../src/lib/api";
import { demoCatalog, demoScenario } from "../src/lib/demo";
import { ProductProvider } from "../src/state/ProductContext";

vi.mock("../src/lib/api", () => ({ DEMO_MODE: true, api: { catalog: vi.fn(), scenarios: vi.fn() } }));

function Destination() {
  return <p>Destination: {useLocation().pathname}</p>;
}

function renderShell(path = "/builder") {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={client}><ProductProvider><MemoryRouter initialEntries={[path]}><Routes><Route element={<AppShell />}><Route path="*" element={<Destination />} /></Route></Routes></MemoryRouter></ProductProvider></QueryClientProvider>);
}

describe("workbench navigation", () => {
  beforeEach(() => {
    vi.stubGlobal("scrollTo", vi.fn());
    vi.mocked(api.catalog).mockResolvedValue(demoCatalog);
    vi.mocked(api.scenarios).mockResolvedValue({ scenarios: [demoScenario] });
  });

  it("labels demo state without claiming a live connection or making a health request", () => {
    const fetcher = vi.fn();
    vi.stubGlobal("fetch", fetcher);
    renderShell();
    expect(screen.getByText("Demo")).toBeVisible();
    expect(screen.queryByText("Connected")).not.toBeInTheDocument();
    expect(screen.queryByText("Local service ready")).not.toBeInTheDocument();
    expect(fetcher).not.toHaveBeenCalled();
  });

  it("keeps the default navigation focused on six work destinations", () => {
    renderShell();
    const navigation = within(screen.getByRole("navigation", { name: "Primary navigation" }));
    expect(navigation.getAllByRole("link").map((link) => link.textContent)).toEqual(["Build", "Runs", "Detection Lab", "Compare", "Experiments", "Settings"]);
    expect(navigation.getByRole("link", { name: "Build" })).toHaveAttribute("href", "/builder");
    expect(navigation.getByRole("link", { name: "Experiments" })).toHaveAttribute("href", "/scenarios");
    expect(navigation.queryByRole("link", { name: "Runner Profiles" })).not.toBeInTheDocument();
  });

  it("reveals every secondary destination with keyboard controls and preserves its route", async () => {
    const user = userEvent.setup();
    renderShell();
    const navigation = within(screen.getByRole("navigation", { name: "Primary navigation" }));
    navigation.getByRole("button", { name: "Show more tools" }).focus();
    await user.keyboard("{Enter}");
    for (const [label, path] of [["Overview", "/"], ["Getting Started", "/getting-started"], ["Behaviors", "/behaviors"], ["Research Sources", "/research-sources"], ["AI Planner", "/ai-planner"], ["Help & Docs", "/help"]]) {
      expect(navigation.getByRole("link", { name: label })).toHaveAttribute("href", path);
    }
    navigation.getByRole("link", { name: "Research Sources" }).focus();
    await user.keyboard("{Enter}");
    expect(screen.getByText("Destination: /research-sources")).toBeVisible();
    expect(navigation.getByRole("link", { name: "Research Sources" })).toHaveAttribute("aria-current", "page");
  });

  it("opens environment tools in Settings and on existing infrastructure deep links", async () => {
    const user = userEvent.setup();
    renderShell("/runner-profiles");
    const navigation = within(screen.getByRole("navigation", { name: "Primary navigation" }));
    expect(navigation.getByRole("button", { name: "Hide settings tools" })).toHaveAttribute("aria-expanded", "true");
    for (const [label, path] of [["Runners", "/runners"], ["Runner Profiles", "/runner-profiles"], ["Actions & Plugins", "/actions"], ["Action Packages", "/action-packages"]]) {
      expect(navigation.getByRole("link", { name: label })).toHaveAttribute("href", path);
    }
    expect(navigation.getByRole("link", { name: "Runner Profiles" })).toHaveAttribute("aria-current", "page");
    await user.click(navigation.getByRole("button", { name: "Hide settings tools" }));
    await user.click(navigation.getByRole("link", { name: "Settings" }));
    expect(navigation.getByRole("link", { name: "Runners" })).toBeVisible();
  });

  it("keeps compact links and disclosures named and operable", async () => {
    const user = userEvent.setup();
    renderShell();
    await user.click(screen.getByRole("button", { name: "Collapse navigation" }));
    const navigation = within(screen.getByRole("navigation", { name: "Primary navigation" }));
    expect(navigation.getByRole("link", { name: "Detection Lab" })).toHaveAccessibleName("Detection Lab");
    navigation.getByRole("button", { name: "Show settings tools" }).focus();
    await user.keyboard(" ");
    await user.click(navigation.getByRole("link", { name: "Action Packages" }));
    expect(screen.getByText("Destination: /action-packages")).toBeVisible();
    expect(screen.getByRole("button", { name: "Expand navigation" })).toBeEnabled();
  });

  it("contains mobile keyboard focus, closes with Escape, and restores the opener", async () => {
    const user = userEvent.setup();
    renderShell();
    const opener = screen.getByRole("button", { name: "Open navigation" });
    await user.click(opener);
    const drawer = screen.getByRole("dialog", { name: "Workspace navigation" });
    expect(drawer).toHaveAttribute("aria-modal", "true");
    expect(within(drawer).getByRole("button", { name: "Close navigation" })).toHaveFocus();
    expect(document.getElementById("main-content")?.parentElement).toHaveAttribute("inert");
    expect(document.body.style.overflow).toBe("hidden");
    within(drawer).getByRole("button", { name: "Show more tools" }).focus();
    await user.keyboard("{Tab}");
    expect(within(drawer).getByRole("link", { name: "BlueFire Nexus home" })).toHaveFocus();
    await user.keyboard("{Escape}");
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(opener).toHaveFocus();
    expect(opener).toHaveAttribute("aria-expanded", "false");
    expect(document.body.style.overflow).toBe("");
  });

  it("keeps run detail links under Runs and supports skipping directly to the workspace", async () => {
    const user = userEvent.setup();
    renderShell("/runs/run-123");
    expect(screen.getByRole("link", { name: "Runs" })).toHaveAttribute("aria-current", "page");
    await user.click(screen.getByRole("link", { name: "Skip to content" }));
    expect(document.getElementById("main-content")).toHaveFocus();
    expect(screen.getByText("Destination: /runs/run-123")).toBeVisible();
  });
});

it("keeps the collapse control in the header with its base styling and restores the layout preference", async () => {
  const user = userEvent.setup();
  localStorage.removeItem("bluefire.navigation.collapsed.v1");
  vi.mocked(api.catalog).mockResolvedValue(demoCatalog);
  vi.mocked(api.scenarios).mockResolvedValue({ scenarios: [demoScenario] });
  const first = renderShell();
  const collapse = screen.getByRole("button", { name: "Collapse navigation" });
  expect(collapse.closest(".sidebar-brand-row")).not.toBeNull();
  expect(collapse).toHaveClass("icon-button", "sidebar-collapse");
  expect(collapse).toHaveAttribute("aria-expanded", "true");
  await user.click(collapse);
  expect(localStorage.getItem("bluefire.navigation.collapsed.v1")).toBe("true");
  expect(screen.getByRole("link", { name: "Build", exact: true })).toHaveClass("nav-link");
  expect(screen.getByRole("link", { name: "Build", exact: true }).getAttribute("class")).not.toContain("=>");
  first.unmount(); renderShell();
  expect(screen.getByRole("button", { name: "Expand navigation" })).toHaveAttribute("aria-expanded", "false");
  expect(document.querySelector(".app-shell")).toHaveClass("nav-collapsed");
});
