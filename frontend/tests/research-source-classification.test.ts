import { describe, expect, it } from "vitest";
import { researchSourceHandling } from "../src/pages/CatalogPages";

describe("research source classification handling", () => {
  it.each([
    ["reference_only", "comparative", "conditional", "metadata_only", false, false],
    ["metadata_import", "imported", "reviewed", "vendored_declarative", false, true],
    ["clean_reimplementation", "inspired", "conditional", "metadata_only", false, false],
    ["external_adapter", "imported", "conditional", "external_only", true, false],
    ["compatible_code_adaptation", "adapted", "reviewed", "vendored_code", true, true],
    ["incompatible_or_restricted", "comparative", "prohibited", "metadata_only", false, false],
  ] as const)(
    "%s derives a valid content boundary",
    (classification, relationship, licenseReview, cachePolicy, executableContent, needsPaths) => {
      expect(researchSourceHandling(classification)).toMatchObject({
        relationship,
        license_review: licenseReview,
        cache_policy: cachePolicy,
        executable_content: executableContent,
        needs_paths: needsPaths,
      });
    },
  );
});
