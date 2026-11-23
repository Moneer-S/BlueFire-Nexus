import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { ident, parse, walk } from "css-tree";
import { describe, expect, it } from "vitest";

function targetsRoot(selectors, inheritedRoot = false) {
  // Finite explicit-root policy, not a cascade or browser selector matcher:
  // the final compound selects the element; html .panel selects a descendant.
  if (selectors.type !== "SelectorList") throw new Error("Expected a parsed CSS selector");
  walk(selectors, (node) => {
    if (node.type === "Raw") throw new Error("Opaque CSS selector cannot satisfy the root contract");
  });
  return selectors.children.toArray().some((selector) => {
    const nodes = selector.children.toArray();
    const compound = nodes.slice(nodes.findLastIndex((node) => node.type === "Combinator") + 1);
    if (compound.some((node) => node.type === "PseudoElementSelector")) return false;
    return compound.some((node) => {
      if (node.type === "TypeSelector") return ident.decode(node.name).toLowerCase() === "html";
      if (node.type === "NestingSelector") return inheritedRoot;
      if (node.type !== "PseudoClassSelector") return false;
      const name = ident.decode(node.name).toLowerCase();
      if (name === "root") return true;
      return (name === "is" || name === "where") && node.children?.toArray()
        .some((nested) => targetsRoot(nested, inheritedRoot));
    });
  });
}

function assertNoRootWidthDeclaration(css) {
  const ast = parse(css, { onParseError: (error) => { throw error; } });
  let rootRules = 0;
  const roots = [];
  walk(ast, {
    enter(node) {
      if (node.type === "Rule") {
        const root = targetsRoot(node.prelude, roots.at(-1) ?? false);
        roots.push(root);
        if (root) rootRules += 1;
      } else if (node.type === "Declaration" && roots.at(-1)) {
        const property = ident.decode(node.property).toLowerCase();
        if (property === "min-width" || property === "min-inline-size") {
          throw new Error("Root CSS must not declare a minimum width");
        }
      }
    },
    leave(node) {
      if (node.type === "Rule") roots.pop();
    },
  });
  expect(rootRules).toBeGreaterThan(0);
}

describe("parsed root width contract", () => {
  it("checks the packaged stylesheet across every rule", () => {
    const root = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
    assertNoRootWidthDeclaration(readFileSync(resolve(root, "bluefire/ui/styles.css"), "utf8"));
  });

  it.each([
    "html { min-width: 600px; }",
    "html, body { min-width: 600px; }",
    "body, html { min-inline-size: 600px; }",
    "@media (max-width: 700px) { html { min-width: 600px; } }",
    "@supports (display: grid) { @media (max-width: 700px) { html, body { min-inline-size: 600px; } } }",
    "html { @media (max-width: 700px) { min-width: 600px; } }",
    ":root { min-inline-size: 600px; }",
    "HTML { MIN-WIDTH: 600px !important; }",
    "\\68tml { min-\\77idth: 600px; }",
    "html.compact { min-width: 600px; }",
    ":is(html, body) { min-width: 600px; }",
    "html { &.compact { min-inline-size: 600px; } }",
  ])("rejects a later root constraint: %s", (laterRule) => {
    expect(() => assertNoRootWidthDeclaration(`html { min-height: 100%; } ${laterRule}`))
      .toThrow("Root CSS must not declare a minimum width");
  });

  it.each([
    "html { min-height: 100%; } /* html { min-width: 600px; } */",
    'html { min-height: 100%; content: "html { min-width: 600px; }"; }',
    "html { --min-width: 600px; } body { min-width: 200px; }",
    'html { min-height: 100%; } [data-name="html"] { min-width: 200px; }',
    "html, body { min-height: 100%; } @media (max-width: 700px) { .html-preview { min-width: 200px; } }",
    "html { min-height: 100%; } html .panel { min-width: 200px; }",
    "html { & > .panel { min-width: 200px; } }",
    "html { min-height: 100%; } html::before { min-width: 200px; }",
    "html { min-height: 100%; } :is(html .panel, body) { min-width: 200px; }",
  ])("keeps comments, strings and non-root declarations distinct: %s", (css) => {
    expect(() => assertNoRootWidthDeclaration(css)).not.toThrow();
  });

  it("does not silently accept an opaque selector", () => {
    expect(() => assertNoRootWidthDeclaration("html { min-height: 100%; } html:unknown(html) { min-width: 600px; }"))
      .toThrow("Opaque CSS selector");
  });
});
