// Catches a failure nobody foresaw while the live view draws a recording, so
// the page says the recording cannot be played instead of going blank.

import { Component } from "react";
import type { ReactNode } from "react";

interface LiveViewBoundaryProps {
  children: ReactNode;
  /** What to show instead, with the failure's own message. */
  fallback: (message: string) => ReactNode;
}

interface LiveViewBoundaryState {
  message: string | null;
}

export class LiveViewBoundary extends Component<LiveViewBoundaryProps, LiveViewBoundaryState> {
  state: LiveViewBoundaryState = { message: null };

  static getDerivedStateFromError(error: unknown): LiveViewBoundaryState {
    return { message: error instanceof Error && error.message ? error.message : "The view failed while drawing it." };
  }

  render(): ReactNode {
    return this.state.message === null ? this.props.children : this.props.fallback(this.state.message);
  }
}
