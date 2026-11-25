// How the watch view shares the height it is given. The step's words (the story
// band) and the transport never give way. When the room is short, the log shows
// fewer lines first (three, two, one, then only its head); then the map takes
// less height, down to the least at which nothing on it lies on another; only
// then does the view grow past the room and the page scroll, with the story band
// below the fold as a whole.

/** The heights the plan is made from, in pixels, as the view measured them. */
export interface RoomParts {
  /** The height the view is given. */
  room: number;
  /** The rows above the map: the head and the race line. */
  above: number;
  /** The story band: the step's sentence, its outcome and the hint under it. */
  band: number;
  /** The transport at the foot. */
  bar: number;
  /** The log's head line above its lines, with the room between them. */
  logHead: number;
  /** The log's head line alone, when the log holds no line and drops that room. */
  logHeadAlone: number;
  /** One line of the log. */
  logLine: number;
  /** The most lines the log holds. */
  most: number;
  /** The height the map keeps while the log gives way: every badge above its host. */
  roomy: number;
  /** The least height of the map: below it, something on the map would lie on another. */
  least: number;
}

export interface RoomPlan {
  /** How many lines the log holds. */
  lines: number;
  /** The least height the map is given: more where the view scrolls, so the story band starts at the fold. */
  map: number;
  /** True when even the map's least height leaves the story band no room above the transport: the view grows and the page scrolls. */
  scroll: boolean;
}

export function planRoom(parts: RoomParts): RoomPlan {
  const rest = parts.room - parts.above - parts.band - parts.bar;
  // What the map has with `lines` lines in the log: a log of no line is its head alone.
  const mapWith = (lines: number) => rest - (lines > 0 ? parts.logHead + lines * parts.logLine : parts.logHeadAlone);
  const roomy = Math.max(parts.least, parts.roomy);
  // The log gives way first, line by line, while the map keeps its roomy height.
  for (let lines = Math.max(0, parts.most); lines >= 0; lines -= 1) {
    if (mapWith(lines) >= roomy) return { lines, map: roomy, scroll: false };
  }
  // Then the map, down to its least height.
  if (mapWith(0) >= parts.least) return { lines: 0, map: parts.least, scroll: false };
  // The map stays at its least height or more, and reaches down to the fold: the story band starts under it, whole.
  return { lines: 0, map: Math.max(parts.least, Math.floor(parts.room - parts.above - parts.logHeadAlone - parts.bar)), scroll: true };
}
