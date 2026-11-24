import { expect } from "@playwright/test";
import type { Page } from "@playwright/test";
import sharp from "sharp";
import { buildTimeline, seekStep } from "../../src/live/playback";
import type { Timeline } from "../../src/live/playback";
import { readRecording } from "../../src/live/recording";

// A short loop of the live view playing, for the top of the README. Every
// frame is the replay page opened paused at one place of the recording (a step
// and how far into it, as the page's address names it), so the same recording
// gives the same frames on any machine: nothing is filmed while it plays.

/** A place of the recording as the page's address names it: a step's id and `at` (0 to 2). */
export interface Place {
  step: string;
  at: number;
}

/** One stretch of playback, from one place to a later one, with the time its first and last frames stay. */
export interface Stretch {
  from: Place;
  to: Place;
  /** Milliseconds the stretch's first frame stays; a frame's own time when left out. */
  holdFirst?: number;
  /** Milliseconds the stretch's last frame stays; a frame's own time when left out. */
  holdLast?: number;
}

export interface LoopPlan {
  /**
   * The stretches the loop plays, one after the other. When the last one ends
   * where the first one starts, its last frame is left out: the loop's own
   * first frame shows that place, so the loop closes with no seam.
   */
  stretches: readonly Stretch[];
  /** Frames shown each second. */
  fps: number;
  /** Seconds of playback at normal speed that one second of the loop shows: below 1 is slower than the view plays. */
  pace: number;
}

/** One frame of the loop: the place it shows and how many milliseconds it stays. */
export interface Frame {
  place: Place;
  delay: number;
}

/** The screen time of a place, as the page itself works it out. */
function timeOf(timeline: Timeline, place: Place): number {
  const time = seekStep(timeline, place.step, place.at);
  if (time === null) throw new Error(`The recording has no step ${place.step}.`);
  return time;
}

/** The place of a screen time: the step on screen then and how far into it, the inverse of `seekStep`. */
export function placeAt(timeline: Timeline, time: number): Place {
  for (const segment of timeline.segments) {
    if (time >= segment.start && time <= segment.end) {
      const length = segment.end - segment.start;
      return { step: segment.step.id, at: length > 0 ? (time - segment.start) / length : 0 };
    }
    const gap = timeline.gaps.find((item) => item.after === segment.index);
    if (gap && time > gap.start && time < gap.end) return { step: segment.step.id, at: 1 + (time - gap.start) / (gap.end - gap.start) };
  }
  throw new Error(`No step is on screen at ${time} s.`);
}

function samePlace(one: Place, other: Place): boolean {
  return one.step === other.step && one.at === other.at;
}

/**
 * The loop's frames: in each stretch, places evenly spaced in playback from
 * `from` to `to`, both included, each shown for one frame's time except the
 * held ones.
 */
export function loopFrames(recordingJson: unknown, plan: LoopPlan): Frame[] {
  const timeline = buildTimeline(readRecording(recordingJson));
  const own = Math.round(1000 / plan.fps);
  const frames: Frame[] = [];
  for (const stretch of plan.stretches) {
    const start = timeOf(timeline, stretch.from);
    const end = timeOf(timeline, stretch.to);
    if (!(end > start)) throw new Error(`A stretch must end after it starts (${stretch.from.step} at ${stretch.from.at}).`);
    const count = Math.max(1, Math.round(((end - start) / plan.pace) * plan.fps));
    for (let index = 0; index <= count; index += 1) {
      // The ends are the plan's own places, so that a held frame shows exactly the place it names.
      const place = index === 0 ? stretch.from : index === count ? stretch.to : placeAt(timeline, start + ((end - start) * index) / count);
      const delay = index === 0 ? (stretch.holdFirst ?? own) : index === count ? (stretch.holdLast ?? own) : own;
      frames.push({ place, delay });
    }
  }
  const [opening] = plan.stretches;
  const closing = plan.stretches[plan.stretches.length - 1];
  if (opening && closing && samePlace(opening.from, closing.to)) frames.pop();
  return frames;
}

/**
 * The view as it stands at its place: the fonts loaded, and every animation
 * that is not held by the pause (a caption rising, a colour changing) at its
 * end, so a frame never catches one halfway.
 */
async function still(page: Page): Promise<void> {
  await page.evaluate(() => document.fonts.ready.then(() => true));
  await expect
    .poll(
      () =>
        page.evaluate(async () => {
          const running = document.getAnimations().filter((item) => item.playState === "running");
          for (const item of running) item.finish();
          await new Promise((done) => requestAnimationFrame(() => requestAnimationFrame(done)));
          return running.length;
        }),
      { timeout: 15_000 },
    )
    .toBe(0);
}

/** One picture of the view paused at each frame's place, as PNG. */
export async function takeFrames(page: Page, open: (query: string) => Promise<void>, frames: readonly Frame[]): Promise<Buffer[]> {
  const pictures: Buffer[] = [];
  for (const { place } of frames) {
    await open(`step=${encodeURIComponent(place.step)}&at=${place.at}&paused=1`);
    await expect(page.getByRole("button", { name: "Play", exact: true })).toBeVisible();
    await still(page);
    pictures.push(await page.screenshot());
  }
  return pictures;
}

/**
 * Writes the pictures as one animated picture that loops for ever, GIF or WebP
 * by the file's name, each shown for its frame's milliseconds. A GIF counts
 * time in hundredths of a second, so fps is best 10, 20 or 25. The pictures
 * are made `width` pixels wide. The GIF is not dithered, so a still part of
 * the view stays the same from one frame to the next.
 */
export async function writeLoop(pictures: readonly Buffer[], frames: readonly Frame[], width: number, file: string): Promise<void> {
  if (pictures.length !== frames.length) throw new Error(`${pictures.length} pictures for ${frames.length} frames.`);
  const delay = frames.map((frame) => frame.delay);
  const sized = await Promise.all(pictures.map((picture) => sharp(picture).resize({ width, kernel: "lanczos3" }).png().toBuffer()));
  const joined = sharp(sized, { join: { animated: true } });
  if (file.endsWith(".webp")) await joined.webp({ delay, loop: 0, quality: 80, smartSubsample: true, effort: 6 }).toFile(file);
  else if (file.endsWith(".gif")) await joined.gif({ delay, loop: 0, dither: 0, effort: 10, interFrameMaxError: 4, interPaletteMaxError: 8 }).toFile(file);
  else throw new Error(`${file}: a loop is a .gif or a .webp file.`);
}
