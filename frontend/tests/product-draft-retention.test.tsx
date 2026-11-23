import { act, render, screen } from "@testing-library/react";
import { expect, it, vi } from "vitest";
import { demoScenario } from "../src/lib/demo";
import { ProductProvider, useProduct } from "../src/state/ProductContext";

const draftKey = "bluefire.local.scenario.v1";
const savedKey = "bluefire.local.scenario-saved.v1";
let product: ReturnType<typeof useProduct>;
function Harness() {
  product = useProduct();
  return <><output aria-label="Dirty">{String(product.dirty)}</output><output aria-label="Document">{JSON.stringify(product.scenario)}</output></>;
}
function mount() { return render(<ProductProvider><Harness/></ProductProvider>); }
function document() { return { ...structuredClone(demoScenario), title: "Operator experiment" }; }

it("leaves a fresh seeded example clean without persisting it as operator work", () => {
  mount();
  expect(screen.getByLabelText("Dirty")).toHaveTextContent("false");
  expect(localStorage.getItem(draftKey)).toBeNull();
  expect(localStorage.getItem(savedKey)).toBeNull();
});

it("retains a manual document and its exact layout as unsaved across reload", () => {
  const first = mount();
  const draft = { ...document(), layout: { [demoScenario.start]: { x: 123, y: 456 } } };
  act(() => product.setScenario(draft));
  first.unmount();
  mount();
  expect(product.scenario).toEqual(draft);
  expect(product.dirty).toBe(true);
  expect(JSON.parse(localStorage.getItem(draftKey)!)).toEqual(draft);
});

it.each(["save", "open"])("restores the exact confirmed %s as clean, then protects a layout-only edit", (operation) => {
  const first = mount();
  const saved = document();
  act(() => {
    product.setScenario(saved, operation !== "open");
    if (operation === "save") expect(product.markSaved(saved)).toBe(true);
  });
  first.unmount();
  const second = mount();
  expect(product.scenario).toEqual(saved);
  expect(product.dirty).toBe(false);
  const moved = { ...saved, layout: { [saved.start]: { x: 789, y: 321 } } };
  act(() => product.setScenario(moved));
  second.unmount();
  mount();
  expect(product.scenario).toEqual(moved);
  expect(product.dirty).toBe(true);
});

it("does not let a late save clear a newer manual draft, including after reload", () => {
  const first = mount();
  const old = document();
  const newer = { ...old, title: "Newer manual work" };
  act(() => product.setScenario(old));
  act(() => product.setScenario(newer));
  act(() => expect(product.markSaved(old)).toBe(false));
  first.unmount();
  mount();
  expect(product.scenario).toEqual(newer);
  expect(product.dirty).toBe(true);
});

it.each(["missing", "invalid", "mismatched", "partial"])("protects a valid cached draft with a %s saved marker", (marker) => {
  const draft = document();
  localStorage.setItem(draftKey, JSON.stringify(draft));
  if (marker !== "missing") localStorage.setItem(savedKey, marker === "invalid" ? "{" : JSON.stringify(marker === "partial" ? { title: draft.title } : { ...draft, title: "Earlier saved work" }));
  mount();
  expect(product.scenario).toEqual(draft);
  expect(product.dirty).toBe(true);
});

it("keeps a persisted draft protected if writing its saved marker fails", () => {
  const first = mount();
  const draft = document();
  act(() => product.setScenario(draft));
  const write = Storage.prototype.setItem;
  const failing = vi.spyOn(Storage.prototype, "setItem").mockImplementation(function (this: Storage, key, value) {
    if (key === savedKey) throw new DOMException("Full", "QuotaExceededError");
    write.call(this, key, value);
  });
  act(() => expect(product.markSaved(draft)).toBe(true));
  first.unmount();
  failing.mockRestore();
  mount();
  expect(product.scenario).toEqual(draft);
  expect(product.dirty).toBe(true);
});
