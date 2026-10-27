/**
 * Presentation-only bands around directly connected runs at their current positions.
 *
 * Pass EVERY visible card's current bounds (including manually moved cards) and
 * the real execution edges. Hidden cards may be included with hidden: true.
 * Conditional edges to the same successor do not invent another branch; distinct
 * destinations/predecessors split runs. No positions or execution fields change.
 *
 * This finds simple connected success chains, not graph-theoretic SCC stages.
 * Simple cycles are deliberately left unbanded. Labels describe actual ordinals,
 * never inferred semantic phases. Rendering must be noninteractive and must not
 * add these rectangles to React Flow's fit, route-obstacle, or execution models.
 */
export interface BandCard {
  readonly id: string;
  readonly ordinal: number;
  readonly x: number;
  readonly y: number;
  readonly width: number;
  readonly height: number;
  readonly hidden?: boolean;
}

export interface BandEdge {
  readonly from_step: string;
  readonly to_step: string;
  readonly outcome: "success" | "partial" | "blocked" | "failed";
}

export interface ConnectedRunBand {
  readonly id: string;
  readonly stepIds: readonly string[];
  readonly ordinals: readonly number[];
  readonly label: string;
  readonly x: number;
  readonly y: number;
  readonly width: number;
  readonly height: number;
}

export interface BandOptions {
  /** Graph units; both card edges must align within this tolerance. */
  readonly alignmentTolerance?: number;
  /** Maximum empty vertical distance between directly connected cards. */
  readonly maxGap?: number;
  readonly padding?: number;
}

// Decorations are optional. Decline very large/dense work instead of blocking
// interaction. Both input traversal and quadratic collision work have hard caps.
const MAX_CARDS = 512;
const MAX_EDGES = 8192;
const MAX_COLLISION_CHECKS = 65536;
type Rect = Pick<BandCard, "x" | "y" | "width" | "height">;
const finiteNonnegative = (value: number) => Number.isFinite(value) && value >= 0;

function bounds(cards: readonly BandCard[], padding: number): Rect {
  const left = Math.min(...cards.map(card => card.x));
  const top = Math.min(...cards.map(card => card.y));
  const right = Math.max(...cards.map(card => card.x + card.width));
  const bottom = Math.max(...cards.map(card => card.y + card.height));
  return { x: left - padding, y: top - padding, width: right - left + padding * 2, height: bottom - top + padding * 2 };
}

function overlaps(left: Rect, right: Rect): boolean {
  return left.x < right.x + right.width && left.x + left.width > right.x
    && left.y < right.y + right.height && left.y + left.height > right.y;
}

function ordinalLabel(ordinals: readonly number[]): string {
  const sorted = [...ordinals].sort((a, b) => a - b);
  const ranges: string[] = [];
  for (let index = 0; index < sorted.length; index += 1) {
    const first = sorted[index]!;
    let last = first;
    while (index + 1 < sorted.length && sorted[index + 1] === last + 1) last = sorted[++index]!;
    ranges.push(first === last ? String(first) : `${first}–${last}`);
  }
  return `Steps ${ranges.join(", ")}`;
}

export function connectedRunBands(
  input: readonly BandCard[],
  edges: readonly BandEdge[],
  options: BandOptions = {},
): ConnectedRunBand[] {
  if (input.length > MAX_CARDS || edges.length > MAX_EDGES) return [];
  const tolerance = options.alignmentTolerance ?? 8;
  const maxGap = options.maxGap ?? 96;
  const padding = options.padding ?? 12;
  if (![tolerance, maxGap, padding].every(finiteNonnegative)) return [];
  const cards = input.filter(card => !card.hidden);
  if (cards.length < 2) return [];
  const byId = new Map<string, BandCard>();
  const ordinals = new Set<number>();
  for (const card of cards) {
    if (!card.id || byId.has(card.id) || !Number.isSafeInteger(card.ordinal) || card.ordinal < 1
      || ordinals.has(card.ordinal) || ![card.x, card.y, card.width, card.height].every(Number.isFinite)
      || card.width <= 0 || card.height <= 0
      || !Number.isFinite(card.x + card.width) || !Number.isFinite(card.y + card.height)) return [];
    byId.set(card.id, card);
    ordinals.add(card.ordinal);
  }
  const outgoing = new Map<string, Set<string>>();
  const incoming = new Map<string, Set<string>>();
  const success = new Map<string, Set<string>>();
  const add = (map: Map<string, Set<string>>, from: string, to: string) => {
    let values = map.get(from);
    if (!values) { values = new Set(); map.set(from, values); }
    values.add(to);
  };
  for (const edge of edges) {
    if (!edge.from_step || !edge.to_step || !["success", "partial", "blocked", "failed"].includes(edge.outcome)) return [];
    // Count real topology even when the other endpoint is outside the visible view.
    if (byId.has(edge.from_step)) add(outgoing, edge.from_step, edge.to_step);
    if (byId.has(edge.to_step)) add(incoming, edge.to_step, edge.from_step);
    if (edge.outcome === "success" && byId.has(edge.from_step) && byId.has(edge.to_step)) add(success, edge.from_step, edge.to_step);
  }
  const topologyNext = new Map<string, string>();
  for (const card of cards) {
    const target = success.get(card.id);
    if (target?.size !== 1 || outgoing.get(card.id)?.size !== 1) continue;
    const next = target.values().next().value as string;
    if (next !== card.id && incoming.get(next)?.size === 1) topologyNext.set(card.id, next);
  }
  // Identify simple success cycles before spatial filtering can disguise a loop
  // as a downward run. Functional links make this traversal linear in card count.
  const completed = new Set<string>();
  const cyclic = new Set<string>();
  for (const card of cards) {
    const path: string[] = [];
    const index = new Map<string, number>();
    let current: string | undefined = card.id;
    while (current && !completed.has(current) && !index.has(current)) {
      index.set(current, path.length); path.push(current); current = topologyNext.get(current);
    }
    if (current && index.has(current)) for (const id of path.slice(index.get(current)!)) cyclic.add(id);
    for (const id of path) completed.add(id);
  }
  const next = new Map<string, string>();
  const previous = new Set<string>();
  for (const [sourceId, targetId] of topologyNext) {
    if (cyclic.has(sourceId) || cyclic.has(targetId)) continue;
    const source = byId.get(sourceId)!;
    const target = byId.get(targetId)!;
    const gap = target.y - (source.y + source.height);
    if (gap < 0 || gap > maxGap || Math.abs(source.x - target.x) > tolerance
      || Math.abs(source.x + source.width - target.x - target.width) > tolerance) continue;
    next.set(sourceId, targetId); previous.add(targetId);
  }
  let checks = 0;
  let exhausted = false;
  const clearOfOthers = (rect: Rect, members: ReadonlySet<string>) => {
    if (![rect.x, rect.y, rect.width, rect.height].every(Number.isFinite)) return false;
    for (const card of cards) {
      if (members.has(card.id)) continue;
      if (++checks > MAX_COLLISION_CHECKS) { exhausted = true; return false; }
      if (overlaps(rect, card)) return false;
    }
    return true;
  };
  const bands: ConnectedRunBand[] = [];
  const emit = (run: readonly BandCard[]) => {
    if (run.length < 2) return;
    const rect = bounds(run, padding);
    const members = new Set(run.map(card => card.id));
    // Final hull check also catches alignment drift and split-chain neighbors.
    // Conservative omission is preferable to enclosing an unrelated card.
    if (!clearOfOthers(rect, members)) return;
    const stepIds = run.map(card => card.id);
    const ordinals = run.map(card => card.ordinal);
    bands.push({ id: `connected-run:${JSON.stringify(stepIds)}`, stepIds, ordinals, label: ordinalLabel(ordinals), ...rect });
  };
  for (const start of cards.filter(card => !previous.has(card.id))) {
    const chain = [start];
    let cursor = start.id;
    while (next.has(cursor)) { cursor = next.get(cursor)!; chain.push(byId.get(cursor)!); }
    if (chain.length < 2) continue;
    const chainIds = new Set(chain.map(card => card.id));
    let run = [chain[0]!];
    for (let index = 1; index < chain.length; index += 1) {
      const currentCard = chain[index]!;
      if (!clearOfOthers(bounds([chain[index - 1]!, currentCard], padding), chainIds)) {
        emit(run); run = [];
      }
      run.push(currentCard);
      if (exhausted) return [];
    }
    emit(run);
    if (exhausted) return [];
  }
  return bands;
}

export interface BranchRegionBand extends ConnectedRunBand {
  readonly kind: "fallback" | "branches";
}

/**
 * Presentation-only regions around a real decision: a step with two or more
 * distinct destinations, those destinations, and the step each alternative
 * rejoins on success. Labelled "fallback" only when every alternative route is
 * a blocked or failed outcome. Declined when the region would enclose an
 * unrelated card or overlap a connected-run band, so it never claims a step it
 * does not contain. Positions are read, never changed.
 */
export function branchRegionBands(
  input: readonly BandCard[],
  edges: readonly BandEdge[],
  existing: readonly ConnectedRunBand[],
  options: Pick<BandOptions, "padding"> = {},
): BranchRegionBand[] {
  if (input.length > MAX_CARDS || edges.length > MAX_EDGES) return [];
  const padding = options.padding ?? 12;
  if (!finiteNonnegative(padding)) return [];
  const cards = input.filter(card => !card.hidden);
  const byId = new Map(cards.map(card => [card.id, card]));
  const banded = new Set(existing.flatMap(band => band.stepIds));
  const taken: Rect[] = existing.map(band => ({ x: band.x, y: band.y, width: band.width, height: band.height }));
  const regions: BranchRegionBand[] = [];
  let checks = 0;
  for (const decision of cards) {
    const outgoing = edges.filter(edge => edge.from_step === decision.id && byId.has(edge.to_step) && edge.to_step !== decision.id);
    const destinations = new Set(outgoing.map(edge => edge.to_step));
    if (destinations.size < 2) continue;
    const primary = outgoing.find(edge => edge.outcome === "success")?.to_step;
    const alternatives = outgoing.filter(edge => edge.to_step !== primary);
    const members = new Set([decision.id, ...destinations]);
    for (const alternative of new Set(alternatives.map(edge => edge.to_step))) {
      const rejoin = edges.find(edge => edge.from_step === alternative && edge.outcome === "success")?.to_step;
      if (rejoin && rejoin !== decision.id && byId.has(rejoin)) members.add(rejoin);
    }
    if (members.size > 6 || [...members].some(id => banded.has(id))) continue;
    const memberCards = [...members].map(id => byId.get(id)!);
    const rect = bounds(memberCards, padding);
    let clear = true;
    for (const card of cards) {
      if (members.has(card.id)) continue;
      if (++checks > MAX_COLLISION_CHECKS) return regions;
      if (overlaps(rect, card)) { clear = false; break; }
    }
    if (!clear || taken.some(other => overlaps(rect, other))) continue;
    // A fallback is the one place a step goes when it does not succeed; any other
    // shape (no success route, or several alternative destinations) is a branch.
    const kind = primary && new Set(alternatives.map(edge => edge.to_step)).size === 1 ? "fallback" : "branches";
    const ordinals = memberCards.map(card => card.ordinal);
    regions.push({ id: `branch-region:${decision.id}`, kind, stepIds: [...members], ordinals, label: `${ordinalLabel(ordinals)} · ${kind}`, ...rect });
    taken.push(rect);
  }
  return regions;
}
