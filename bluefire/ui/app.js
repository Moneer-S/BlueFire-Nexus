"use strict";

const API = "/api/v1";
const OUTCOMES = ["success", "partial", "blocked", "failed"];
const TERMINAL_STATES = new Set(["succeeded", "success", "partial", "blocked", "failed", "refused", "cancelled"]);
const SVG_NS = "http://www.w3.org/2000/svg";

const state = {
  catalog: [],
  profiles: [],
  scenarios: [],
  graph: {
    title: "Control validation path",
    version: 1,
    nodes: [],
  },
  selectedNodeId: null,
  selectedCapability: "all",
  validation: null,
  preflight: null,
  runs: [],
  activeRun: null,
  activeRunTimer: null,
  detailView: "planner",
  comparison: null,
  drag: null,
};

const byId = (id) => document.getElementById(id);

function element(tag, className = "", text = "") {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text) node.textContent = text;
  return node;
}

function svgElement(tag, attributes = {}) {
  const node = document.createElementNS(SVG_NS, tag);
  for (const [name, value] of Object.entries(attributes)) {
    node.setAttribute(name, String(value));
  }
  return node;
}

function asArray(value, keys = []) {
  if (Array.isArray(value)) return value;
  if (!value || typeof value !== "object") return [];
  for (const key of keys) {
    if (Array.isArray(value[key])) return value[key];
  }
  if (value.data && typeof value.data === "object") return asArray(value.data, keys);
  return [];
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function brief(value, fallback = "—") {
  if (value === null || value === undefined || value === "") return fallback;
  if (Array.isArray(value)) return value.length ? value.join(", ") : fallback;
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

async function request(path, options = {}) {
  const init = {
    method: options.method || "GET",
    credentials: "same-origin",
    headers: { Accept: "application/json" },
  };
  if (options.body !== undefined) {
    init.headers["Content-Type"] = "application/json";
    init.body = JSON.stringify(options.body);
  }
  const response = await fetch(`${API}${path}`, init);
  const contentType = response.headers.get("Content-Type") || "";
  const payload = contentType.includes("application/json") ? await response.json() : null;
  if (!response.ok) {
    const message = payload?.error?.message || `Request failed with status ${response.status}`;
    const error = new Error(message);
    error.code = payload?.error?.code || "request_failed";
    error.details = payload?.error?.details;
    throw error;
  }
  return payload;
}

let toastTimer = null;
function announce(message, kind = "info") {
  const toast = byId("app-status");
  toast.textContent = message;
  toast.dataset.state = kind;
  toast.hidden = false;
  window.clearTimeout(toastTimer);
  toastTimer = window.setTimeout(() => {
    toast.hidden = true;
  }, 5200);
}

function setConnection(ready) {
  const indicator = byId("connection-state");
  indicator.dataset.state = ready ? "ready" : "error";
  indicator.lastElementChild.textContent = ready ? "Local service ready" : "Local service unavailable";
}

function normalizeCatalog(payload) {
  const behaviors = asArray(payload, ["behaviors", "items", "catalog"])
    .filter((item) => item && typeof item === "object" && typeof item.id === "string")
    .map((item) => ({
      id: item.id,
      title: item.title || item.name || item.id,
      purpose: item.purpose || item.description || "No purpose statement provided.",
      safety_tier: item.safety_tier || "safe",
      execution_state: item.execution_state || "metadata_only",
      capabilities: Array.isArray(item.capabilities) ? item.capabilities : [],
      platforms: Array.isArray(item.platforms) ? item.platforms : [],
      inputs: Array.isArray(item.inputs) ? item.inputs : [],
      outputs: Array.isArray(item.outputs) ? item.outputs : [],
      parameters: Array.isArray(item.parameters) ? item.parameters : [],
      limitations: Array.isArray(item.limitations) ? item.limitations : [],
      compatible_behaviors: Array.isArray(item.compatible_behaviors) ? item.compatible_behaviors : [],
    }));
  const profiles = asArray(payload, ["profiles", "runner_profiles"]);
  return { behaviors, profiles };
}

function behaviorFor(node) {
  return state.catalog.find((behavior) => behavior.id === node?.behavior_id) || null;
}

function nodeFor(nodeId) {
  return state.graph.nodes.find((node) => node.id === nodeId) || null;
}

function makeStepId(title) {
  const root = String(title || "step")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "")
    .replace(/^[^a-z]+/, "") || "step";
  let candidate = root;
  let suffix = 2;
  while (nodeFor(candidate)) {
    candidate = `${root}_${suffix}`;
    suffix += 1;
  }
  return candidate;
}

function defaultParameterValue(spec) {
  if (spec.default !== undefined && spec.default !== null) return clone(spec.default);
  if (Array.isArray(spec.enum) && spec.enum.length) return spec.enum[0];
  if (spec.type === "boolean") return false;
  if (spec.type === "integer" || spec.type === "number") return spec.minimum ?? 0;
  if (spec.type === "string_list") return [];
  return "";
}

function addBehavior(behaviorId, position = null) {
  const behavior = state.catalog.find((item) => item.id === behaviorId);
  if (!behavior) return;
  const index = state.graph.nodes.length;
  const parameters = {};
  for (const spec of behavior.parameters) {
    if (spec.required || spec.default !== undefined) parameters[spec.name] = defaultParameterValue(spec);
  }
  const node = {
    id: makeStepId(behavior.title),
    behavior_id: behavior.id,
    title: behavior.title,
    x: position?.x ?? 70 + (index % 3) * 320,
    y: position?.y ?? 75 + Math.floor(index / 3) * 190,
    parameters,
    inputs: {},
    alternates: [],
    outcomes: {},
    status: "queued",
  };
  const previous = state.graph.nodes.at(-1);
  if (previous && !previous.outcomes.success) previous.outcomes.success = node.id;
  state.graph.nodes.push(node);
  state.selectedNodeId = node.id;
  invalidateChecks();
  renderGraph();
  renderInspector();
  announce(`${behavior.title} added to the graph.`, "success");
}

function removeSelectedNode() {
  const nodeId = state.selectedNodeId;
  if (!nodeId) return;
  state.graph.nodes = state.graph.nodes.filter((node) => node.id !== nodeId);
  for (const node of state.graph.nodes) {
    for (const outcome of OUTCOMES) {
      if (node.outcomes[outcome] === nodeId) delete node.outcomes[outcome];
    }
    for (const [port, binding] of Object.entries(node.inputs)) {
      if (binding.from_step === nodeId) delete node.inputs[port];
    }
  }
  state.selectedNodeId = state.graph.nodes[0]?.id || null;
  invalidateChecks();
  renderGraph();
  renderInspector();
  announce("Node removed from the draft.");
}

function invalidateChecks() {
  state.validation = null;
  state.preflight = null;
  byId("start-run").disabled = true;
  renderValidation();
  renderPreflight();
}

function stableScenarioId() {
  const title = byId("scenario-title").value || "local experiment";
  const stem = title.toLowerCase().replace(/[^a-z0-9]+/g, ".").replace(/^\.+|\.+$/g, "") || "local.experiment";
  const safeStem = /^[a-z]/.test(stem) ? stem : `scenario.${stem}`;
  const version = Math.max(1, Number.parseInt(byId("scenario-version").value, 10) || 1);
  return `${safeStem}.v${version}`;
}

function scenarioDocument() {
  const title = byId("scenario-title").value.trim() || "Local experiment";
  const steps = state.graph.nodes.map((node) => ({
    id: node.id,
    behavior_id: node.behavior_id,
    parameters: clone(node.parameters),
    inputs: clone(node.inputs),
    alternates: clone(node.alternates),
  }));
  const edges = [];
  for (const node of state.graph.nodes) {
    for (const outcome of OUTCOMES) {
      if (node.outcomes[outcome]) {
        edges.push({ from_step: node.id, outcome, to_step: node.outcomes[outcome] });
      }
    }
  }
  return {
    schema_version: "bluefire.scenario.v1",
    id: stableScenarioId(),
    title,
    purpose: `Validate the observable outcomes and defensive controls for ${title}.`,
    start: steps[0]?.id || "missing_start",
    steps,
    edges,
    provenance: {
      source: "local operator draft",
      reference: "browser session",
      license: "private",
      derived: true,
      notes: "Created in the local BlueFire experiment console.",
    },
    limitations: ["Scope and runner readiness are resolved during preflight."],
  };
}

function graphRequest() {
  return {
    scenario: scenarioDocument(),
    layout: {
      schema_version: "bluefire.layout.v1",
      nodes: state.graph.nodes.map((node) => ({ id: node.id, x: Math.round(node.x), y: Math.round(node.y) })),
    },
  };
}

function runRequest() {
  const mode = document.querySelector('input[name="execution-mode"]:checked')?.value || "simulate";
  const execute = mode === "execute";
  return {
    ...graphRequest(),
    mode,
    ai_enabled: byId("ai-planner").checked,
    runner_profile_id: byId("runner-profile").value || null,
    target_scope: { scope_refs: [byId("scope-reference").value.trim()] },
    approval: {
      confirmed: execute && byId("execute-approval-confirm").checked,
      approved_by: execute ? byId("approval-operator").value.trim() : "",
    },
  };
}

function executionMode() {
  return document.querySelector('input[name="execution-mode"]:checked')?.value || "simulate";
}

function executeApprovalReady() {
  return executionMode() !== "execute" || (
    byId("execute-approval-confirm").checked && Boolean(byId("approval-operator").value.trim())
  );
}

function syncExecuteApproval() {
  const execute = executionMode() === "execute";
  const panel = byId("execute-approval");
  const confirmation = byId("execute-approval-confirm");
  const operator = byId("approval-operator");
  panel.hidden = !execute;
  confirmation.required = execute;
  operator.required = execute;
  if (!execute) {
    confirmation.checked = false;
    operator.value = "";
  }
  invalidateChecks();
}

function renderPalette() {
  const query = byId("behavior-search").value.trim().toLowerCase();
  const filtered = state.catalog.filter((behavior) => {
    const matchesCapability = state.selectedCapability === "all" || behavior.capabilities.includes(state.selectedCapability);
    const haystack = [behavior.id, behavior.title, behavior.purpose, ...behavior.capabilities, ...behavior.platforms].join(" ").toLowerCase();
    return matchesCapability && (!query || haystack.includes(query));
  });
  const list = byId("behavior-list");
  list.replaceChildren();
  for (const behavior of filtered) {
    const card = element("button", "behavior-card");
    card.type = "button";
    card.draggable = true;
    card.dataset.behaviorId = behavior.id;
    card.setAttribute("aria-label", `Add ${behavior.title} to graph`);
    card.append(element("strong", "", behavior.title));
    card.append(element("small", "", behavior.purpose));
    const tags = element("span", "tag-row");
    const tier = element("span", `tag tier-${behavior.safety_tier}`, behavior.safety_tier);
    tags.append(tier);
    for (const capability of behavior.capabilities.slice(0, 2)) tags.append(element("span", "tag", capability));
    card.append(tags);
    card.addEventListener("click", () => addBehavior(behavior.id));
    card.addEventListener("dragstart", (event) => {
      event.dataTransfer?.setData("application/x-bluefire-behavior", behavior.id);
      if (event.dataTransfer) event.dataTransfer.effectAllowed = "copy";
    });
    list.append(card);
  }
  if (!filtered.length) list.append(element("p", "panel-hint", "No behaviors match this filter."));
  byId("behavior-count").textContent = String(filtered.length);
}

function renderCapabilityFilters() {
  const capabilities = [...new Set(state.catalog.flatMap((behavior) => behavior.capabilities))].sort();
  const row = byId("capability-filters");
  row.replaceChildren();
  for (const capability of ["all", ...capabilities]) {
    const button = element("button", `filter-chip${capability === state.selectedCapability ? " is-active" : ""}`, capability);
    button.type = "button";
    button.setAttribute("aria-pressed", String(capability === state.selectedCapability));
    button.addEventListener("click", () => {
      state.selectedCapability = capability;
      renderCapabilityFilters();
      renderPalette();
    });
    row.append(button);
  }
}

function renderEdges() {
  const edgeLayer = byId("graph-edges");
  edgeLayer.replaceChildren();
  for (const source of state.graph.nodes) {
    for (const outcome of OUTCOMES) {
      const target = nodeFor(source.outcomes[outcome]);
      if (!target) continue;
      const startX = source.x + 220;
      const startY = source.y + 58;
      const endX = target.x;
      const endY = target.y + 58;
      const direction = Math.max(70, Math.abs(endX - startX) * 0.45);
      const path = svgElement("path", {
        class: `graph-edge ${outcome}`,
        d: `M ${startX} ${startY} C ${startX + direction} ${startY}, ${endX - direction} ${endY}, ${endX} ${endY}`,
      });
      edgeLayer.append(path);
      const label = svgElement("text", {
        class: "graph-edge-label",
        x: (startX + endX) / 2,
        y: (startY + endY) / 2 - 8,
        "text-anchor": "middle",
      });
      label.textContent = outcome;
      edgeLayer.append(label);
    }
  }
}

function renderGraph() {
  renderEdges();
  const nodeLayer = byId("graph-nodes");
  nodeLayer.replaceChildren();
  byId("graph-empty").hidden = state.graph.nodes.length > 0;
  state.graph.nodes.forEach((node, index) => {
    const behavior = behaviorFor(node);
    const group = svgElement("g", {
      class: `graph-node${node.id === state.selectedNodeId ? " is-selected" : ""}`,
      transform: `translate(${node.x} ${node.y})`,
      tabindex: "0",
      role: "button",
      "aria-label": `${node.title}, graph node ${index + 1}`,
      "data-node-id": node.id,
    });
    group.append(svgElement("rect", { class: "node-shell", width: 220, height: 116, rx: 12 }));
    group.append(svgElement("rect", { class: "node-accent", width: 4, height: 116, rx: 2 }));
    const indexText = svgElement("text", { class: "node-index", x: 18, y: 24 });
    indexText.textContent = String(index + 1).padStart(2, "0");
    const title = svgElement("text", { class: "node-title", x: 18, y: 49 });
    title.textContent = truncate(node.title, 27);
    const id = svgElement("text", { class: "node-id", x: 18, y: 72 });
    id.textContent = truncate(node.id, 31);
    const tier = svgElement("text", { class: "node-tier", x: 18, y: 97 });
    tier.textContent = behavior?.safety_tier || "unknown";
    group.append(indexText, title, id, tier);
    const inputCount = behavior?.inputs.length || 0;
    const outputCount = behavior?.outputs.length || 0;
    for (let port = 0; port < Math.min(3, inputCount); port += 1) {
      group.append(svgElement("circle", { class: "node-port input", cx: 0, cy: 42 + port * 18, r: 5 }));
    }
    for (let port = 0; port < Math.min(3, outputCount); port += 1) {
      group.append(svgElement("circle", { class: "node-port output", cx: 220, cy: 42 + port * 18, r: 5 }));
    }
    group.addEventListener("click", () => selectNode(node.id));
    group.addEventListener("keydown", (event) => moveNodeWithKeyboard(event, node));
    group.addEventListener("pointerdown", (event) => beginNodeDrag(event, node));
    nodeLayer.append(group);
  });
}

function truncate(value, limit) {
  const text = String(value || "");
  return text.length > limit ? `${text.slice(0, limit - 1)}…` : text;
}

function selectNode(nodeId) {
  state.selectedNodeId = nodeId;
  renderGraph();
  renderInspector();
}

function moveNodeWithKeyboard(event, node) {
  if (event.key === "Enter" || event.key === " ") {
    event.preventDefault();
    selectNode(node.id);
    return;
  }
  if (event.key === "Delete" || event.key === "Backspace") {
    event.preventDefault();
    state.selectedNodeId = node.id;
    removeSelectedNode();
    return;
  }
  const moves = { ArrowLeft: [-16, 0], ArrowRight: [16, 0], ArrowUp: [0, -16], ArrowDown: [0, 16] };
  if (!moves[event.key]) return;
  event.preventDefault();
  node.x = Math.max(10, Math.min(890, node.x + moves[event.key][0]));
  node.y = Math.max(10, Math.min(490, node.y + moves[event.key][1]));
  invalidateChecks();
  renderGraph();
  requestAnimationFrame(() => document.querySelector(`[data-node-id="${node.id}"]`)?.focus());
}

function graphPoint(event) {
  const svg = byId("graph-canvas");
  const point = svg.createSVGPoint();
  point.x = event.clientX;
  point.y = event.clientY;
  const matrix = svg.getScreenCTM();
  return matrix ? point.matrixTransform(matrix.inverse()) : { x: event.clientX, y: event.clientY };
}

function beginNodeDrag(event, node) {
  if (event.button !== 0) return;
  state.selectedNodeId = node.id;
  for (const candidate of document.querySelectorAll(".graph-node")) {
    candidate.classList.toggle("is-selected", candidate.dataset.nodeId === node.id);
  }
  renderInspector();
  const point = graphPoint(event);
  state.drag = { node, dx: point.x - node.x, dy: point.y - node.y, pointerId: event.pointerId };
  event.currentTarget.setPointerCapture(event.pointerId);
}

function moveNodeDrag(event) {
  if (!state.drag || state.drag.pointerId !== event.pointerId) return;
  const point = graphPoint(event);
  state.drag.node.x = Math.max(10, Math.min(890, point.x - state.drag.dx));
  state.drag.node.y = Math.max(10, Math.min(490, point.y - state.drag.dy));
  const group = document.querySelector(`[data-node-id="${state.drag.node.id}"]`);
  group?.setAttribute("transform", `translate(${state.drag.node.x} ${state.drag.node.y})`);
  renderEdges();
}

function endNodeDrag(event) {
  if (!state.drag || state.drag.pointerId !== event.pointerId) return;
  state.drag = null;
  invalidateChecks();
}

function outputChoices(targetNode, inputSpec) {
  const choices = [];
  for (const sourceNode of state.graph.nodes) {
    if (sourceNode.id === targetNode.id) continue;
    const sourceBehavior = behaviorFor(sourceNode);
    for (const output of sourceBehavior?.outputs || []) {
      if (output.type === inputSpec.type && Boolean(output.multiple) === Boolean(inputSpec.multiple)) {
        choices.push({ from_step: sourceNode.id, artifact: output.name, label: `${sourceNode.id} · ${output.name}` });
      }
    }
  }
  return choices;
}

function signature(behavior) {
  const specs = (items) => items.map((item) => [item.name, item.type, Boolean(item.required), Boolean(item.multiple)]);
  const parameters = behavior.parameters.map((item) => [item.name, item.type, Boolean(item.required), item.enum || []]);
  return JSON.stringify([specs(behavior.inputs), specs(behavior.outputs), parameters]);
}

function compatibleBehaviors(behavior) {
  if (!behavior) return [];
  const declared = new Set(behavior.compatible_behaviors || []);
  const targetSignature = signature(behavior);
  return state.catalog.filter((candidate) => candidate.id !== behavior.id && (declared.has(candidate.id) || signature(candidate) === targetSignature));
}

function renderInspector() {
  const host = byId("node-inspector");
  host.replaceChildren();
  const node = nodeFor(state.selectedNodeId);
  const behavior = behaviorFor(node);
  byId("remove-node").disabled = !node;
  if (!node || !behavior) {
    const empty = element("div", "empty-inspector");
    empty.append(element("strong", "", "No node selected"), element("span", "", "Select a node on the graph to inspect its contract."));
    host.append(empty);
    return;
  }

  const identity = element("section", "inspector-section");
  identity.append(element("h3", "", behavior.title), element("p", "", behavior.purpose));
  const idLabel = element("label");
  idLabel.append(element("span", "", "Step ID"));
  const idInput = element("input");
  idInput.value = node.id;
  idInput.pattern = "[a-z][a-z0-9_]*";
  idInput.addEventListener("change", () => renameNode(node, idInput.value));
  idLabel.append(idInput);
  identity.append(idLabel);
  const tags = element("div", "tag-row");
  tags.append(element("span", `tag tier-${behavior.safety_tier}`, behavior.safety_tier));
  for (const platform of behavior.platforms) tags.append(element("span", "tag", platform));
  identity.append(tags);
  host.append(identity);

  const inputs = element("section", "inspector-section");
  inputs.append(element("h3", "", "Typed inputs"));
  if (!behavior.inputs.length) inputs.append(element("p", "", "This behavior has no artifact inputs."));
  for (const spec of behavior.inputs) {
    const slot = element("div", "contract-slot");
    slot.append(element("strong", "", spec.name), element("code", "", spec.type));
    slot.append(element("small", "", spec.required ? "Required binding" : "Optional binding"));
    const select = element("select");
    select.setAttribute("aria-label", `Binding for ${spec.name}`);
    select.append(new Option(spec.required ? "Choose compatible output" : "No binding", ""));
    for (const choice of outputChoices(node, spec)) select.append(new Option(choice.label, `${choice.from_step}:${choice.artifact}`));
    const current = node.inputs[spec.name];
    if (current) select.value = `${current.from_step}:${current.artifact}`;
    select.addEventListener("change", () => {
      if (!select.value) delete node.inputs[spec.name];
      else {
        const [fromStep, artifact] = select.value.split(":", 2);
        node.inputs[spec.name] = { from_step: fromStep, artifact };
      }
      invalidateChecks();
    });
    slot.append(select);
    inputs.append(slot);
  }
  host.append(inputs);

  const outputs = element("section", "inspector-section");
  outputs.append(element("h3", "", "Typed outputs"));
  if (!behavior.outputs.length) outputs.append(element("p", "", "This behavior emits no downstream artifacts."));
  for (const spec of behavior.outputs) {
    const slot = element("div", "contract-slot");
    slot.append(element("strong", "", spec.name), element("code", "", spec.type));
    slot.append(element("small", "", spec.multiple ? "Artifact collection" : "Single artifact"));
    outputs.append(slot);
  }
  host.append(outputs);

  if (behavior.parameters.length) {
    const parameters = element("section", "inspector-section");
    parameters.append(element("h3", "", "Parameters"));
    for (const spec of behavior.parameters) parameters.append(parameterControl(node, spec));
    host.append(parameters);
  }

  const routes = element("section", "inspector-section");
  routes.append(element("h3", "", "Explicit outcome edges"));
  for (const outcome of OUTCOMES) {
    const row = element("label", "outcome-row");
    row.append(element("span", "", outcome));
    const select = element("select");
    select.append(new Option("End path", ""));
    for (const candidate of state.graph.nodes.filter((item) => item.id !== node.id)) select.append(new Option(candidate.id, candidate.id));
    select.value = node.outcomes[outcome] || "";
    select.addEventListener("change", () => {
      if (select.value) node.outcomes[outcome] = select.value;
      else delete node.outcomes[outcome];
      invalidateChecks();
      renderGraph();
    });
    row.append(select);
    routes.append(row);
  }
  host.append(routes);

  const swap = element("section", "inspector-section");
  swap.append(element("h3", "", "Compatible swap"));
  const candidates = compatibleBehaviors(behavior);
  if (!candidates.length) swap.append(element("p", "", "No behavior with an identical typed contract is registered."));
  const list = element("div", "swap-list");
  for (const candidate of candidates) {
    const button = element("button", "", candidate.title);
    button.type = "button";
    button.addEventListener("click", () => swapBehavior(node, candidate));
    list.append(button);
  }
  swap.append(list);
  host.append(swap);
}

function parameterControl(node, spec) {
  const label = element("label", "parameter-field");
  label.append(element("span", "", spec.name));
  let input;
  if (Array.isArray(spec.enum) && spec.enum.length) {
    input = element("select");
    for (const value of spec.enum) input.append(new Option(String(value), String(value)));
  } else if (spec.type === "boolean") {
    input = element("select");
    input.append(new Option("False", "false"), new Option("True", "true"));
  } else {
    input = element("input");
    input.type = spec.type === "integer" || spec.type === "number" ? "number" : "text";
    if (spec.minimum !== null && spec.minimum !== undefined) input.min = String(spec.minimum);
    if (spec.maximum !== null && spec.maximum !== undefined) input.max = String(spec.maximum);
    if (spec.type === "number") input.step = "any";
  }
  const value = node.parameters[spec.name] ?? defaultParameterValue(spec);
  input.value = Array.isArray(value) ? value.join(", ") : String(value);
  input.required = Boolean(spec.required);
  input.addEventListener("change", () => {
    if (spec.type === "boolean") node.parameters[spec.name] = input.value === "true";
    else if (spec.type === "integer") node.parameters[spec.name] = Number.parseInt(input.value, 10);
    else if (spec.type === "number") node.parameters[spec.name] = Number(input.value);
    else if (spec.type === "string_list") node.parameters[spec.name] = input.value.split(",").map((item) => item.trim()).filter(Boolean);
    else node.parameters[spec.name] = input.value;
    invalidateChecks();
  });
  label.append(input);
  return label;
}

function renameNode(node, requested) {
  const next = requested.trim();
  if (!/^[a-z][a-z0-9_]*$/.test(next) || (next !== node.id && nodeFor(next))) {
    announce("Step IDs must be unique lowercase snake_case values.", "error");
    renderInspector();
    return;
  }
  const previous = node.id;
  node.id = next;
  for (const candidate of state.graph.nodes) {
    for (const outcome of OUTCOMES) if (candidate.outcomes[outcome] === previous) candidate.outcomes[outcome] = next;
    for (const binding of Object.values(candidate.inputs)) if (binding.from_step === previous) binding.from_step = next;
  }
  state.selectedNodeId = next;
  invalidateChecks();
  renderGraph();
  renderInspector();
}

function swapBehavior(node, behavior) {
  node.behavior_id = behavior.id;
  node.title = behavior.title;
  node.parameters = Object.fromEntries(behavior.parameters.filter((spec) => spec.required || spec.default !== undefined).map((spec) => [spec.name, defaultParameterValue(spec)]));
  invalidateChecks();
  renderGraph();
  renderInspector();
  announce(`Swapped node to ${behavior.title}.`, "success");
}

function renderValidation() {
  const drawer = byId("validation-drawer");
  const summary = drawer.firstElementChild;
  const list = byId("validation-list");
  list.replaceChildren();
  if (!state.validation) {
    drawer.dataset.state = "idle";
    summary.firstElementChild.textContent = "Draft not validated";
    summary.lastElementChild.textContent = "Run graph validation to inspect contracts and reachability.";
    return;
  }
  const valid = state.validation.valid === true || state.validation.status === "valid";
  drawer.dataset.state = valid ? "valid" : "invalid";
  summary.firstElementChild.textContent = valid ? "Graph contract is valid" : "Graph needs attention";
  const issues = asArray(state.validation, ["issues", "errors", "findings"]);
  summary.lastElementChild.textContent = valid ? `${state.graph.nodes.length} nodes are ready for preflight.` : `${issues.length || 1} validation finding${issues.length === 1 ? "" : "s"}.`;
  for (const issue of issues) {
    list.append(element("li", "", typeof issue === "string" ? issue : issue.message || issue.code || brief(issue)));
  }
}

async function validateGraph() {
  if (!state.graph.nodes.length) {
    announce("Add at least one behavior before validation.", "error");
    return;
  }
  const button = byId("validate-graph");
  button.disabled = true;
  try {
    state.validation = await request("/scenarios/validate", { method: "POST", body: graphRequest() });
    renderValidation();
    const valid = state.validation?.valid === true || state.validation?.status === "valid";
    announce(valid ? "Graph validation passed." : "Graph validation returned findings.", valid ? "success" : "error");
  } catch (error) {
    state.validation = { valid: false, issues: error.details || [error.message] };
    renderValidation();
    announce(error.message, "error");
  } finally {
    button.disabled = false;
  }
}

function renderPreflight() {
  const preflight = state.preflight;
  const badge = byId("readiness-badge");
  if (!preflight) {
    badge.dataset.state = "idle";
    badge.textContent = "Not checked";
    for (const id of ["preflight-profile", "preflight-scope", "preflight-capabilities", "preflight-tier", "preflight-approval", "preflight-cleanup"]) byId(id).textContent = "—";
    byId("preflight-findings").textContent = "Run preflight to resolve policy and runner readiness.";
    return;
  }
  const ready = preflight.ready === true || preflight.allowed === true || preflight.status === "ready";
  badge.dataset.state = ready ? "ready" : "blocked";
  badge.textContent = ready ? "Ready" : "Blocked";
  byId("preflight-profile").textContent = brief(preflight.runner_profile || preflight.profile || byId("runner-profile").value);
  byId("preflight-scope").textContent = brief(preflight.scope || byId("scope-reference").value);
  byId("preflight-capabilities").textContent = brief(preflight.capabilities || preflight.capability_checks);
  byId("preflight-tier").textContent = brief(preflight.safety_tier || preflight.tier);
  byId("preflight-approval").textContent = executionMode() === "simulate"
    ? "Not applicable in Simulate"
    : brief(preflight.approval || (preflight.approval_required ? "Required" : "Confirmed"));
  byId("preflight-cleanup").textContent = brief(preflight.cleanup || preflight.cleanup_plan);
  const findings = asArray(preflight, ["findings", "issues", "warnings"]);
  byId("preflight-findings").textContent = findings.length ? findings.map((item) => typeof item === "string" ? item : item.message || brief(item)).join(" · ") : (ready ? "Policy, capability, scope, approval, and cleanup checks passed." : "Preflight did not authorize this run.");
  byId("start-run").disabled = !ready;
}

async function requestPreflight() {
  if (!state.graph.nodes.length) {
    announce("Build a graph before requesting preflight.", "error");
    return;
  }
  if (!executeApprovalReady()) {
    announce("Execute preflight requires explicit approval and an operator identity.", "error");
    byId("execute-approval-confirm").focus();
    return;
  }
  const button = byId("request-preflight");
  button.disabled = true;
  try {
    state.preflight = await request("/runs/preflight", { method: "POST", body: runRequest() });
    renderPreflight();
    const ready = state.preflight?.ready === true || state.preflight?.allowed === true || state.preflight?.status === "ready";
    announce(ready ? "Preflight passed. Review the resolved controls before starting." : "Preflight blocked this intent.", ready ? "success" : "error");
  } catch (error) {
    state.preflight = { ready: false, findings: error.details || [error.message] };
    renderPreflight();
    announce(error.message, "error");
  } finally {
    button.disabled = false;
  }
}

async function startRun() {
  if (!executeApprovalReady()) {
    invalidateChecks();
    announce("Execute approval changed. Confirm it and run preflight again.", "error");
    return;
  }
  const button = byId("start-run");
  button.disabled = true;
  try {
    const result = await request("/runs", { method: "POST", body: runRequest() });
    state.activeRun = result;
    renderActiveRun();
    await loadRuns();
    scheduleRunRefresh();
    announce(`Run ${result.run_id || "created"} started.`, "success");
  } catch (error) {
    announce(error.message, "error");
    button.disabled = false;
  }
}

function runSteps(run) {
  return asArray(run, ["steps", "nodes", "path"]);
}

function renderActiveRun() {
  const run = state.activeRun;
  const host = byId("live-graph");
  host.replaceChildren();
  if (!run) {
    byId("active-run-label").textContent = "None";
    host.append(element("p", "", "No active run. Complete preflight to begin."));
    renderDetailView();
    return;
  }
  byId("active-run-label").textContent = run.run_id || "Pending identifier";
  const steps = runSteps(run);
  if (!steps.length) host.append(element("p", "", `Run status: ${run.status || "created"}. Waiting for node events.`));
  for (const item of steps) {
    const card = element("article", "live-node");
    card.dataset.status = item.status || "queued";
    card.append(element("strong", "", item.title || item.name || item.step_id || item.id || "Node"));
    card.append(element("small", "", item.status || "queued"));
    host.append(card);
  }
  renderDetailView();
}

function detailPayload(run, view) {
  const aliases = {
    planner: ["planner", "plan", "proposals"],
    policy: ["policy", "policy_decisions"],
    runner: ["runner", "runner_events"],
    evidence: ["evidence", "evidence_records"],
    detections: ["detections", "detection_candidates"],
  };
  for (const key of aliases[view]) if (run?.[key] !== undefined) return run[key];
  return null;
}

function renderDetailView() {
  const host = byId("run-detail-view");
  host.replaceChildren();
  const payload = detailPayload(state.activeRun, state.detailView);
  if (payload === null || payload === undefined || (Array.isArray(payload) && !payload.length)) {
    host.append(element("p", "muted", `No ${state.detailView} records are available yet.`));
    return;
  }
  const entries = Array.isArray(payload) ? payload : Object.entries(payload).map(([key, value]) => ({ key, value }));
  const list = element("dl");
  for (const [index, item] of entries.entries()) {
    const key = item.key || item.id || item.event_type || item.type || `${state.detailView} ${index + 1}`;
    const value = item.value !== undefined ? item.value : item.message || item.status || item;
    list.append(element("dt", "", String(key)), element("dd", "", brief(value)));
  }
  host.append(list);
}

function scheduleRunRefresh() {
  window.clearTimeout(state.activeRunTimer);
  const runId = state.activeRun?.run_id;
  if (!runId || TERMINAL_STATES.has(String(state.activeRun.status || "").toLowerCase())) return;
  state.activeRunTimer = window.setTimeout(async () => {
    try {
      state.activeRun = await request(`/runs/${encodeURIComponent(runId)}`);
      renderActiveRun();
      scheduleRunRefresh();
    } catch (error) {
      announce(`Run refresh paused: ${error.message}`, "error");
    }
  }, 1800);
}

function normalizeRuns(payload) {
  return asArray(payload, ["runs", "items"]).filter((run) => run && typeof run === "object" && typeof run.run_id === "string");
}

async function loadRuns() {
  try {
    state.runs = normalizeRuns(await request("/runs"));
    renderRunHistory();
  } catch (error) {
    announce(`Run history unavailable: ${error.message}`, "error");
  }
}

function renderRunHistory() {
  const selected = new Set([...document.querySelectorAll('#run-list input[type="checkbox"]:checked')].map((input) => input.value));
  const host = byId("run-list");
  host.replaceChildren();
  const replaySource = byId("replay-source");
  const previousReplay = replaySource.value;
  replaySource.replaceChildren(new Option("Select a run", ""));
  for (const run of state.runs) {
    const label = element("label", "run-row");
    const checkbox = element("input");
    checkbox.type = "checkbox";
    checkbox.value = run.run_id;
    checkbox.checked = selected.has(run.run_id);
    checkbox.addEventListener("change", updateRunSelection);
    const copy = element("span");
    copy.append(element("strong", "", run.run_id), element("small", "", `${run.scenario_title || run.scenario_name || "Experiment"} · ${run.created_at || run.started_at || "time unavailable"}`));
    label.append(checkbox, copy, element("em", "", run.status || "unknown"));
    host.append(label);
    replaySource.append(new Option(`${run.run_id} · ${run.status || "unknown"}`, run.run_id));
  }
  if (!state.runs.length) host.append(element("p", "panel-hint", "No run bundles are available yet."));
  replaySource.value = state.runs.some((run) => run.run_id === previousReplay) ? previousReplay : "";
  populateReplayProfiles();
  updateRunSelection();
}

function updateRunSelection() {
  const count = document.querySelectorAll('#run-list input[type="checkbox"]:checked').length;
  byId("selected-run-count").textContent = String(count);
  byId("compare-runs").disabled = count < 2;
}

function profileId(profile) {
  return profile.id || profile.profile_id || profile.name || "";
}

function profileTitle(profile) {
  return profile.title || profile.name || profileId(profile);
}

function populateProfiles() {
  const runProfile = byId("runner-profile");
  runProfile.replaceChildren(new Option("Select a profile", ""));
  for (const profile of state.profiles) runProfile.append(new Option(profileTitle(profile), profileId(profile)));
  populateReplayProfiles();
}

function populateReplayProfiles() {
  const select = byId("replay-profile");
  const previous = select.value;
  select.replaceChildren(new Option("Preserve original", ""));
  for (const profile of state.profiles) select.append(new Option(profileTitle(profile), profileId(profile)));
  select.value = previous;
}

async function loadReplaySource() {
  const runId = byId("replay-source").value;
  const fromNode = byId("replay-from-node");
  const swapNode = byId("replay-swap-node");
  const swap = byId("replay-swap");
  fromNode.replaceChildren(new Option("Select node", ""));
  swapNode.replaceChildren(new Option("Select node", ""));
  swap.replaceChildren(new Option("Select compatible behavior", ""));
  if (!runId) return;
  try {
    const run = await request(`/runs/${encodeURIComponent(runId)}`);
    for (const step of runSteps(run)) {
      const id = step.step_id || step.id;
      if (id) {
        const label = step.title || step.name || id;
        fromNode.append(new Option(label, id));
        swapNode.append(new Option(label, id));
      }
    }
    for (const behavior of state.catalog) swap.append(new Option(behavior.title, behavior.id));
  } catch (error) {
    announce(error.message, "error");
  }
}

async function createReplay() {
  const runId = byId("replay-source").value;
  if (!runId) {
    announce("Select a source run before creating a replay.", "error");
    return;
  }
  const strategy = document.querySelector('input[name="replay-strategy"]:checked')?.value || "exact";
  const aiOverride = byId("replay-ai").value;
  const requestBody = {
    strategy,
    exact: strategy === "exact",
    from_step_id: strategy === "from_node" ? byId("replay-from-node").value || null : null,
    swap_step_id: strategy === "swap" ? byId("replay-swap-node").value || null : null,
    swap_behavior_id: strategy === "swap" ? byId("replay-swap").value || null : null,
    runner_profile_id: byId("replay-profile").value || null,
    ai_enabled: aiOverride === "preserve" ? null : aiOverride === "enabled",
    defense_change: byId("defense-change").value.trim() || null,
  };
  try {
    const result = await request(`/runs/${encodeURIComponent(runId)}/replays`, { method: "POST", body: requestBody });
    state.activeRun = result;
    renderActiveRun();
    scheduleRunRefresh();
    await loadRuns();
    announce(`Replay ${result.run_id || "created"} is linked to ${runId}.`, "success");
  } catch (error) {
    announce(error.message, "error");
  }
}

async function compareSelectedRuns() {
  const runIds = [...document.querySelectorAll('#run-list input[type="checkbox"]:checked')].map((input) => input.value);
  if (runIds.length < 2) return;
  const button = byId("compare-runs");
  button.disabled = true;
  try {
    state.comparison = await request("/comparisons", { method: "POST", body: { run_ids: runIds } });
    renderComparison(runIds);
    announce("Comparison generated from canonical run records.", "success");
  } catch (error) {
    announce(error.message, "error");
    byId("comparison-state").dataset.state = "error";
    byId("comparison-state").textContent = "Unavailable";
  } finally {
    button.disabled = false;
  }
}

function renderComparison(runIds) {
  const comparison = state.comparison || {};
  const badge = byId("comparison-state");
  badge.dataset.state = "ready";
  badge.textContent = `${runIds.length} runs`;
  const summaries = asArray(comparison, ["summaries"]);
  const summaryValues = (key, fallbackKey = null) => summaries.length
    ? summaries.map((item) => `${item.run_id || "run"}: ${brief(item[key] ?? (fallbackKey ? item[fallbackKey] : undefined))}`).join(" · ")
    : undefined;
  const fields = [
    comparison.first_blocked_node ?? comparison.first_blocked ?? summaryValues("first_blocked_step"),
    comparison.objective_reached ?? comparison.objective ?? summaryValues("objective_reached"),
    comparison.evidence_provenance ?? comparison.provenance ?? summaryValues("evidence_provenance"),
    comparison.detection_lifecycle ?? comparison.detections ?? summaryValues("detection_states"),
    comparison.cleanup_result ?? comparison.cleanup ?? summaryValues("cleanup_success"),
    comparison.latency_delta ?? comparison.latency ?? "Not recorded",
  ];
  const cards = byId("comparison-summary").children;
  fields.forEach((value, index) => { cards[index].lastElementChild.textContent = brief(value); });
  const graph = byId("comparison-graph");
  graph.replaceChildren();
  const lanes = asArray(comparison, ["runs", "lanes", "paths", "summaries"]);
  const laneData = lanes.length ? lanes : runIds.map((runId) => ({ run_id: runId, steps: [] }));
  for (const lane of laneData) {
    const article = element("article", "compare-lane");
    article.append(element("h3", "", lane.run_id || lane.id || "Run"));
    const list = element("ol");
    const steps = asArray(lane, ["steps", "nodes", "path"]);
    if (!steps.length) list.append(element("li", "", brief(lane.status, "Path details unavailable")));
    for (const step of steps) {
      if (typeof step === "string") list.append(element("li", "", `${step} · ${lane.outcomes?.[step] || "unknown"}`));
      else list.append(element("li", "", `${step.title || step.name || step.step_id || step.id || "Node"} · ${step.status || step.outcome || "unknown"}`));
    }
    article.append(list);
    graph.append(article);
  }
}

function loadScenarioDocument(documentValue) {
  const scenario = documentValue?.scenario || documentValue;
  if (!scenario || !Array.isArray(scenario.steps)) return;
  const layoutItems = asArray(documentValue?.layout, ["nodes"]);
  const positions = new Map(layoutItems.map((item) => [item.id, item]));
  const outcomes = new Map();
  for (const edge of scenario.edges || []) {
    if (!outcomes.has(edge.from_step)) outcomes.set(edge.from_step, {});
    outcomes.get(edge.from_step)[edge.outcome] = edge.to_step;
  }
  state.graph.nodes = scenario.steps.map((step, index) => {
    const behavior = state.catalog.find((item) => item.id === step.behavior_id);
    const position = positions.get(step.id);
    return {
      id: step.id,
      behavior_id: step.behavior_id,
      title: behavior?.title || step.behavior_id,
      x: Number(position?.x ?? 70 + (index % 3) * 320),
      y: Number(position?.y ?? 75 + Math.floor(index / 3) * 190),
      parameters: clone(step.parameters || {}),
      inputs: clone(step.inputs || {}),
      alternates: clone(step.alternates || []),
      outcomes: outcomes.get(step.id) || {},
      status: "queued",
    };
  });
  state.selectedNodeId = state.graph.nodes[0]?.id || null;
  byId("scenario-title").value = scenario.title || "Local experiment";
  const versionMatch = String(scenario.id || "").match(/\.v([1-9][0-9]*)$/);
  byId("scenario-version").value = versionMatch?.[1] || "1";
  invalidateChecks();
  renderGraph();
  renderInspector();
}

function renderScenarioPicker() {
  const picker = byId("scenario-picker");
  picker.replaceChildren(new Option("Current draft", ""));
  state.scenarios.forEach((scenario, index) => picker.append(new Option(scenario.title || scenario.name || scenario.id || `Scenario ${index + 1}`, String(index))));
}

function duplicateGraph() {
  const copy = clone(state.graph);
  copy.title = `${byId("scenario-title").value.trim() || "Experiment"} copy`;
  state.graph = copy;
  byId("scenario-title").value = copy.title;
  byId("scenario-version").value = "1";
  invalidateChecks();
  renderGraph();
  renderInspector();
  announce("Draft duplicated in this browser session.", "success");
}

function exportGraph() {
  const blob = new Blob([`${JSON.stringify(graphRequest(), null, 2)}\n`], { type: "application/json" });
  const link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = `${stableScenarioId()}.json`;
  link.click();
  window.setTimeout(() => URL.revokeObjectURL(link.href), 0);
  announce("Draft exported as local JSON.", "success");
}

function fitGraph() {
  state.graph.nodes.forEach((node, index) => {
    node.x = 70 + (index % 3) * 320;
    node.y = 75 + Math.floor(index / 3) * 190;
  });
  invalidateChecks();
  renderGraph();
}

function switchWorkspace(button) {
  const workspace = button.dataset.workspace;
  for (const tab of document.querySelectorAll(".workspace-tab")) {
    const active = tab === button;
    tab.classList.toggle("is-active", active);
    tab.setAttribute("aria-selected", String(active));
    tab.tabIndex = active ? 0 : -1;
    const panel = byId(`workspace-${tab.dataset.workspace}`);
    panel.hidden = !active;
    panel.classList.toggle("is-active", active);
  }
  if (workspace === "compare") loadRuns();
}

function tabKeyboardNavigation(event, buttons, activate) {
  const current = buttons.indexOf(event.currentTarget);
  let target = current;
  if (event.key === "ArrowRight") target = (current + 1) % buttons.length;
  else if (event.key === "ArrowLeft") target = (current - 1 + buttons.length) % buttons.length;
  else if (event.key === "Home") target = 0;
  else if (event.key === "End") target = buttons.length - 1;
  else return;
  event.preventDefault();
  buttons[target].focus();
  activate(buttons[target]);
}

function setupEvents() {
  const workspaceButtons = [...document.querySelectorAll(".workspace-tab")];
  workspaceButtons.forEach((button) => {
    button.addEventListener("click", () => switchWorkspace(button));
    button.addEventListener("keydown", (event) => tabKeyboardNavigation(event, workspaceButtons, switchWorkspace));
  });
  byId("behavior-search").addEventListener("input", renderPalette);
  byId("validate-graph").addEventListener("click", validateGraph);
  byId("duplicate-graph").addEventListener("click", duplicateGraph);
  byId("export-graph").addEventListener("click", exportGraph);
  byId("fit-graph").addEventListener("click", fitGraph);
  byId("remove-node").addEventListener("click", removeSelectedNode);
  byId("scenario-title").addEventListener("change", invalidateChecks);
  byId("scenario-version").addEventListener("change", invalidateChecks);
  byId("scenario-picker").addEventListener("change", (event) => {
    if (event.target.value !== "") loadScenarioDocument(state.scenarios[Number(event.target.value)]);
  });
  byId("open-validation").addEventListener("click", (event) => {
    const list = byId("validation-list");
    list.hidden = !list.hidden;
    event.currentTarget.setAttribute("aria-expanded", String(!list.hidden));
    event.currentTarget.textContent = list.hidden ? "Show details" : "Hide details";
  });
  for (const control of document.querySelectorAll('input[name="execution-mode"]')) control.addEventListener("change", syncExecuteApproval);
  for (const control of document.querySelectorAll('#ai-planner, #runner-profile, #execute-approval-confirm')) control.addEventListener("change", invalidateChecks);
  for (const control of document.querySelectorAll('#scope-reference, #approval-operator')) control.addEventListener("input", invalidateChecks);
  byId("request-preflight").addEventListener("click", requestPreflight);
  byId("start-run").addEventListener("click", startRun);
  const detailTabs = [...document.querySelectorAll("[data-detail-view]")];
  detailTabs.forEach((button) => {
    button.addEventListener("click", () => {
      state.detailView = button.dataset.detailView;
      detailTabs.forEach((candidate) => {
        const selected = candidate === button;
        candidate.setAttribute("aria-selected", String(selected));
        candidate.tabIndex = selected ? 0 : -1;
      });
      renderDetailView();
    });
    button.addEventListener("keydown", (event) => tabKeyboardNavigation(event, detailTabs, (target) => target.click()));
  });
  byId("refresh-runs").addEventListener("click", loadRuns);
  byId("replay-source").addEventListener("change", loadReplaySource);
  byId("create-replay").addEventListener("click", createReplay);
  byId("compare-runs").addEventListener("click", compareSelectedRuns);
  const stage = byId("graph-stage");
  stage.addEventListener("dragover", (event) => {
    if (event.dataTransfer?.types.includes("application/x-bluefire-behavior")) event.preventDefault();
  });
  stage.addEventListener("drop", (event) => {
    const behaviorId = event.dataTransfer?.getData("application/x-bluefire-behavior");
    if (!behaviorId) return;
    event.preventDefault();
    const point = graphPoint(event);
    addBehavior(behaviorId, { x: Math.max(10, point.x - 110), y: Math.max(10, point.y - 58) });
  });
  const canvas = byId("graph-canvas");
  canvas.addEventListener("pointermove", moveNodeDrag);
  canvas.addEventListener("pointerup", endNodeDrag);
  canvas.addEventListener("pointercancel", endNodeDrag);
}

async function bootstrap() {
  setupEvents();
  syncExecuteApproval();
  renderGraph();
  renderInspector();
  renderValidation();
  renderPreflight();
  try {
    const [catalogPayload, scenarioPayload, runPayload] = await Promise.all([
      request("/catalog"),
      request("/scenarios"),
      request("/runs"),
    ]);
    const normalized = normalizeCatalog(catalogPayload);
    state.catalog = normalized.behaviors;
    state.profiles = normalized.profiles;
    state.scenarios = asArray(scenarioPayload, ["scenarios", "items"]);
    state.runs = normalizeRuns(runPayload);
    renderCapabilityFilters();
    renderPalette();
    renderScenarioPicker();
    populateProfiles();
    renderRunHistory();
    if (state.scenarios.length) loadScenarioDocument(state.scenarios[0]);
    else if (state.catalog.length) {
      state.catalog.slice(0, Math.min(4, state.catalog.length)).forEach((behavior) => addBehavior(behavior.id));
      announce("Started a local draft from the behavior registry.");
    }
    setConnection(true);
  } catch (error) {
    setConnection(false);
    renderCapabilityFilters();
    renderPalette();
    announce(`The local service is unavailable: ${error.message}`, "error");
  }
}

bootstrap();
