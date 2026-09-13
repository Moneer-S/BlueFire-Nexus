type ProviderDescription = { id?: unknown; provider_id?: unknown; kind?: unknown; model?: unknown; config?: unknown };

const apiNames = new Map([
  ["deterministic", "Offline deterministic planner"],
  ["openai_responses", "Responses API"],
  ["chat_completions", "Chat Completions API"],
]);
const knownKinds = new Map([
  ["deterministic-offline.v1", "deterministic"],
  ["openai-responses.v1", "openai_responses"],
  ["chat-completions.v1", "chat_completions"],
]);

/** Display only: never rewrite a provider document or its authorization identity. */
export function providerLabel(source: ProviderDescription): string {
  const config = source.config && typeof source.config === "object" && !Array.isArray(source.config)
    ? source.config as ProviderDescription : source;
  const id = config.id ?? config.provider_id;
  const kind = typeof config.kind === "string" ? config.kind : typeof id === "string" ? knownKinds.get(id) : undefined;
  const name = kind ? apiNames.get(kind) ?? "Model connection" : "Model connection";
  const model = typeof config.model === "string" ? config.model.trim() : "";
  return kind === "deterministic" || !model ? name : `${name} · ${model}`;
}

/** IDs disambiguate otherwise identical names; the readable label remains first. */
export function providerChoiceLabel(provider: ProviderDescription & { provider_id: string }, providers: readonly ProviderDescription[]): string {
  const label = providerLabel(provider);
  return providers.filter(item => providerLabel(item) === label).length > 1
    ? `${label} · ${provider.provider_id}` : label;
}
