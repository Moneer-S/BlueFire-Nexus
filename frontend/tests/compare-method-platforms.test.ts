import { expect, it } from "vitest";
import { platformRestriction } from "../src/pages/Compare";

// sandbox.collection.atomic-gzip.v1 declares platforms: [linux] in bluefire/catalog/actions.yaml.
// It is contract-compatible with the JSONL collector, so the replay picker offered it on Windows,
// where the policy engine then refused the step because the action, profile and requested platform
// do not intersect. The picker must name that restriction before dispatch.
it("names a single-platform method so a Windows operator sees the restriction first", () => {
  expect(platformRestriction(["linux"])).toBe(" · Linux only");
});

it("names a two-platform restriction with both names", () => {
  expect(platformRestriction(["linux", "macos"])).toBe(" · Linux / macOS only");
});

it("stays silent for methods that run everywhere", () => {
  expect(platformRestriction(["linux", "macos", "windows"])).toBe("");
});

it("stays silent when the catalog reports no usable platform", () => {
  expect(platformRestriction([])).toBe("");
  expect(platformRestriction(undefined)).toBe("");
  expect(platformRestriction(["sandbox"])).toBe("");
});
