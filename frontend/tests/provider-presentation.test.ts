import { expect, it } from "vitest";
import { providerChoiceLabel, providerLabel } from "../src/lib/provider-presentation";

it.each([
  ["deterministic provider", { provider_id: "deterministic-offline.v1", kind: "deterministic", model: "deterministic-planner.v1" }, "Offline deterministic planner"],
  ["Responses provider", { id: "openai-responses.v1", kind: "openai_responses", model: "configured-model" }, "Responses API · configured-model"],
  ["nested Chat Completions configuration", { config: { id: "custom.lab.v1", kind: "chat_completions", model: "lab-model" } }, "Chat Completions API · lab-model"],
  ["configured kind overrides familiar ID", { id: "openai-responses.v1", kind: "chat_completions", model: "other-model" }, "Chat Completions API · other-model"],
  ["unknown provider ID", { id: "unfamiliar.v1" }, "Model connection"],
  ["malformed nested configuration", { config: [], kind: "unrecognized", model: "known-model" }, "Model connection · known-model"],
  ["prototype kind", { kind: "__proto__", model: "" }, "Model connection"],
  ["constructor kind", { kind: "constructor", model: "" }, "Model connection"],
  ["non-string provider ID", { id: { toString: null, valueOf: null } }, "Model connection"],
])("derives a readable label without changing source metadata: %s", (_case, source, expected) => {
  const original = structuredClone(source);
  expect(providerLabel(source)).toBe(expected);
  expect(source).toEqual(original);
});

it("disambiguates connections with the same API and model without replacing their IDs", () => {
  const connections = [
    { provider_id: "primary.connection.v1", kind: "openai_responses", model: "same-model" },
    { provider_id: "alternate.connection.v1", kind: "openai_responses", model: "same-model" },
  ];
  expect(providerChoiceLabel(connections[0]!, connections)).toBe("Responses API · same-model · primary.connection.v1");
  expect(providerChoiceLabel(connections[1]!, connections)).toBe("Responses API · same-model · alternate.connection.v1");
});
