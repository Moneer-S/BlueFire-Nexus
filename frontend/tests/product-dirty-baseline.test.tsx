import { act, render } from "@testing-library/react";
import { expect, it, vi } from "vitest";
import { demoScenario } from "../src/lib/demo";
import { ProductProvider, useProduct } from "../src/state/ProductContext";

const draftKey = "bluefire.local.scenario.v1";
const savedKey = "bluefire.local.scenario-saved.v1";
let product: ReturnType<typeof useProduct>;
function Harness() { product = useProduct(); return null; }
function mount() { return render(<ProductProvider><Harness/></ProductProvider>); }
function savedDocument() { return { ...structuredClone(demoScenario), title: "Saved collection procedure" }; }
function warnsBeforeLeaving() {
  const event = new Event("beforeunload", { cancelable: true });
  window.dispatchEvent(event);
  return event.defaultPrevented;
}

it.each(["open", "save"])("clears dirty after a full edit/revert to the %s baseline but never restores approval", operation => {
  mount();
  const saved = savedDocument();
  act(() => {
    product.setScenario(saved, operation !== "open");
    if (operation === "save") expect(product.markSaved(saved)).toBe(true);
  });
  act(() => product.setScenario({ ...saved, title: "Temporary title" }));
  expect(product.dirty).toBe(true);
  expect(warnsBeforeLeaving()).toBe(true);
  act(() => product.setRunConfig({ ...product.runConfig, approved: true, approvedBy: "operator" }));
  expect(product.runConfig.approved).toBe(true);
  act(() => product.setScenario(structuredClone(saved)));
  expect(product.dirty).toBe(false);
  expect(warnsBeforeLeaving()).toBe(false);
  expect(product.runConfig).toMatchObject({ approved: false, approvedBy: "" });
  expect(JSON.parse(localStorage.getItem(savedKey)!)).toEqual(saved);
});

it("hydrates the full earlier saved baseline even when the restored draft differs", () => {
  const saved = savedDocument();
  const edited = { ...saved, title: "Persisted unsaved title" };
  localStorage.setItem(savedKey, JSON.stringify(saved));
  localStorage.setItem(draftKey, JSON.stringify(edited));
  const first = mount();
  expect(product.scenario).toEqual(edited);
  expect(product.dirty).toBe(true);
  act(() => product.setScenario(structuredClone(saved)));
  expect(product.dirty).toBe(false);
  first.unmount();
  mount();
  expect(product.scenario).toEqual(saved);
  expect(product.dirty).toBe(false);
});

it("keeps layout differences dirty when the original title is restored", () => {
  mount();
  const saved = savedDocument();
  act(() => product.setScenario(saved, false));
  const moved = { ...saved, title: "Temporary title", layout: { [saved.start]: { x: 321, y: 654 } } };
  act(() => product.setScenario(moved));
  act(() => product.setScenario({ ...moved, title: saved.title }));
  expect(product.dirty).toBe(true);
  expect(warnsBeforeLeaving()).toBe(true);
  act(() => product.setScenario(structuredClone(saved)));
  expect(product.dirty).toBe(false);
});

it("cannot replace the active baseline or clear later edits with a stale save response", () => {
  mount();
  const saved = savedDocument();
  const submitted = { ...saved, title: "Save in flight" };
  act(() => product.setScenario(saved, false));
  act(() => product.setScenario(submitted));
  act(() => product.setScenario({ ...submitted, title: "Later edit" }));
  act(() => expect(product.markSaved(submitted)).toBe(false));
  expect(product.dirty).toBe(true);
  expect(product.scenario.title).toBe("Later edit");
  expect(JSON.parse(localStorage.getItem(savedKey)!)).toEqual(saved);
  act(() => product.setScenario(structuredClone(saved)));
  expect(product.dirty).toBe(false);
});

it.each([null, "{", JSON.stringify({ title: "Saved collection procedure" })])("protects an unknown saved baseline across edit/revert (%s)", marker => {
  const draft = savedDocument();
  localStorage.setItem(draftKey, JSON.stringify(draft));
  if (marker !== null) localStorage.setItem(savedKey, marker);
  mount();
  act(() => product.setScenario({ ...draft, title: "Temporary title" }));
  act(() => product.setScenario(draft));
  expect(product.dirty).toBe(true);
  expect(warnsBeforeLeaving()).toBe(true);
});

it("retains a known in-memory baseline on storage failure but protects the reloaded draft", () => {
  const first = mount();
  const saved = savedDocument();
  const original = Storage.prototype.setItem;
  const write = vi.spyOn(Storage.prototype, "setItem").mockImplementation(function (this: Storage, key, value) {
    if (key === savedKey) throw new DOMException("Full", "QuotaExceededError");
    original.call(this, key, value);
  });
  act(() => product.setScenario(saved, false));
  act(() => product.setScenario({ ...saved, title: "Temporary title" }));
  act(() => product.setScenario(saved));
  expect(product.dirty).toBe(false);
  first.unmount();
  write.mockRestore();
  mount();
  expect(product.scenario).toEqual(saved);
  expect(product.dirty).toBe(true);
});

it("can revert an edited fresh example without inventing a saved marker", () => {
  mount();
  const initial = structuredClone(product.scenario);
  act(() => product.setScenario({ ...initial, title: "Temporary title" }));
  act(() => product.setScenario(initial));
  expect(product.dirty).toBe(false);
  expect(localStorage.getItem(savedKey)).toBeNull();
});

it("does not normalize a partial saved marker into a clean baseline", () => {
  const draft = { ...savedDocument(), limitations: [] };
  const marker = JSON.parse(JSON.stringify(draft)) as Record<string, unknown>;
  delete marker.limitations;
  localStorage.setItem(savedKey, JSON.stringify(marker));
  localStorage.setItem(draftKey, JSON.stringify(draft));
  mount();
  expect(product.dirty).toBe(true);
  act(() => product.setScenario({ ...draft, title: "Temporary title" }));
  act(() => product.setScenario(draft));
  expect(product.dirty).toBe(true);
});
