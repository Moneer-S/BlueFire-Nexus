/** Resolve the run ID from its labeled canonical identity row, not duplicate raw text. */
export function readCanonicalRunIdentity(documentRef = globalThis.document) {
  const identityDisclosure = "Run identity, environment and technical record";
  const sections = [...documentRef.querySelectorAll(".historical-run-page details.run-review-details")]
    .filter((details) => [...details.children].some((child) =>
      child.tagName === "SUMMARY" && child.textContent?.trim() === identityDisclosure));
  const rows = sections.flatMap((section) => [...section.querySelectorAll(".data-list > div")]
    .filter((row) => row.querySelector("dt")?.textContent?.trim() === "Run ID"));
  const values = rows.flatMap((row) => [...row.querySelectorAll("dd .copy-record-id > code")]);
  return {
    identity_sections: sections.length,
    run_id_rows: rows.length,
    run_id_values: values.length,
    run_id: values.length === 1 ? values[0]?.textContent?.trim() ?? "" : "",
  };
}
