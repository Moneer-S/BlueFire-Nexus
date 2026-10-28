import { beforeEach, describe, expect, it } from "vitest";
import { readCanonicalRunIdentity } from "./installed/run-result-identity.mjs";

describe("canonical run identity lookup", () => {
  beforeEach(() => {
    document.body.innerHTML = "";
  });

  it("selects the labeled Run ID when the same text appears elsewhere in the review", () => {
    const runId = "run-0123456789abcdef0123456789abcdef";
    document.body.innerHTML = `<main class="historical-run-page">
      <section aria-label="Selected run"><span>${runId}</span></section>
      <details class="run-review-details">
        <summary>Run identity, environment and technical record</summary>
        <dl class="data-list"><div><dt>Run ID</dt><dd><span class="copy-record-id"><code>${runId}</code><button>Copy run ID</button></span></dd></div></dl>
        <details><summary>Raw reproducibility metadata</summary><pre aria-label="Canonical run technical record">{"run_id":"${runId}"}</pre></details>
      </details>
    </main>`;

    const exactTextMatches = [...document.querySelectorAll(".historical-run-page span, .historical-run-page code")]
      .filter((element) => element.textContent?.trim() === runId);
    expect(exactTextMatches).toHaveLength(2);
    expect(readCanonicalRunIdentity()).toEqual({
      identity_sections: 1,
      run_id_rows: 1,
      run_id_values: 1,
      run_id: runId,
    });
  });

  it("rejects an ambiguous duplicate Run ID row instead of choosing either value", () => {
    document.body.innerHTML = `<main class="historical-run-page">
      <details class="run-review-details"><summary>Run identity, environment and technical record</summary>
        <dl class="data-list">
          <div><dt>Run ID</dt><dd><span class="copy-record-id"><code>run-a</code></span></dd></div>
          <div><dt>Run ID</dt><dd><span class="copy-record-id"><code>run-b</code></span></dd></div>
        </dl>
      </details>
    </main>`;

    expect(readCanonicalRunIdentity()).toEqual({
      identity_sections: 1,
      run_id_rows: 2,
      run_id_values: 2,
      run_id: "",
    });
  });
});
