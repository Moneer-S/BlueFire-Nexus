// Small pieces of motion. Each one is a CSS animation that starts when it is
// mounted, set back by how long ago its moment was, so a paused or scrubbed
// view shows it at the right point. The clock never re-renders them.

import { useState } from "react";
import type { CSSProperties } from "react";

export type StyleVars = CSSProperties & { [key: `--${string}`]: string | number };

interface MotionProps {
  className: string;
  /** Screen seconds since the moment this motion shows. */
  age: number;
  /** Screen seconds the motion lasts. */
  length: number;
  speed: number;
  style?: StyleVars;
}

/** One CSS animation, timed at mount from its age and the playback speed. */
export function Motion({ className, age, length, speed, style }: MotionProps) {
  const [timing] = useState(() => ({ duration: length / speed, delay: -age / speed }));
  const own: StyleVars = { ...style, animationDuration: `${timing.duration}s`, animationDelay: `${timing.delay}s` };
  return <div className={className} style={own} aria-hidden="true" />;
}
