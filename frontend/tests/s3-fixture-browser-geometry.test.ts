import { expect, it } from "vitest";
import { outsideMainElements } from "./s3-fixture-browser-support";

function setBounds(node: Element, left: number, right: number) {
  Object.defineProperty(node, "getBoundingClientRect", {
    configurable: true,
    value: () => ({ x: left, y: 0, left, right, top: 0, bottom: 10, width: right - left, height: 10, toJSON: () => ({}) }),
  });
}

it("checks visible summaries and overflow-hidden escapes while allowing only closed bodies and scroll clipping", () => {
  document.body.innerHTML = `
    <main>
      <details><summary><a href="#visible">Visible summary link</a></summary><p>Hidden body</p><details><summary>Nested hidden summary</summary><p>Nested body</p></details></details>
      <div class="intentional-scroll"><article>Scrollable lane</article></div>
      <div class="hidden-overflow"><article>Potentially truncated content</article></div>
    </main>`;
  const main = document.querySelector("main")!;
  const details = main.querySelector<HTMLDetailsElement>(":scope > details")!;
  const scroller = main.querySelector<HTMLElement>(".intentional-scroll")!;
  const hiddenOverflow = main.querySelector<HTMLElement>(".hidden-overflow")!;
  const summary = details.querySelector(":scope > summary")!;
  const summaryLink = summary.querySelector("a")!;
  const bodyText = details.querySelector(":scope > p")!;
  const nestedSummary = details.querySelector(":scope > details > summary")!;
  const scrollArticle = scroller.querySelector("article")!;
  const hiddenArticle = hiddenOverflow.querySelector("article")!;
  scroller.style.overflowX = "auto";
  hiddenOverflow.style.overflowX = "hidden";
  setBounds(main, 0, 100);
  setBounds(details, 0, 100);
  setBounds(summary, -5, 30);
  setBounds(summaryLink, -4, 20);
  setBounds(bodyText, -20, 40);
  setBounds(nestedSummary, -10, 35);
  setBounds(scroller, 0, 100);
  setBounds(scrollArticle, 10, 180);
  setBounds(hiddenOverflow, 0, 100);
  setBounds(hiddenArticle, 10, 110);

  const outside = outsideMainElements();
  expect(outside.map(item => item.tag)).toEqual(["SUMMARY", "A", "ARTICLE"]);
  expect(outside[2]).toMatchObject({ className: "", bounds: { left: 10, right: 110 }, visibleBounds: { left: 10, right: 110 }, clippedBy: null });
});
