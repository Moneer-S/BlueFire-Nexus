import "@testing-library/jest-dom/vitest";
import { cleanup } from "@testing-library/react";
import { afterEach, vi } from "vitest";

afterEach(() => {
  cleanup();
  window.localStorage.clear();
  window.sessionStorage.clear();
  window.location.hash = "";
  vi.restoreAllMocks();
});

class TestResizeObserver {
  observe() {}
  unobserve() {}
  disconnect() {}
}

Object.defineProperty(globalThis, "ResizeObserver", { writable: true, value: TestResizeObserver });
// jsdom does not implement DOMMatrixReadOnly. React Flow reads only m22 to
// normalize handle coordinates by its viewport's translate/scale transform.
class TestDOMMatrixReadOnly {
  readonly m22: number;
  constructor(transform = "") {
    const matrix = transform.match(/^matrix(3d)?\(([^)]+)\)$/);
    if (matrix) {
      const values = matrix[2]!.split(",").map(Number);
      this.m22 = values[matrix[1] ? 5 : 3]!;
    } else {
      const scale = transform.match(/(?:^|\s)scale\(([^)]+)\)/);
      const values = scale?.[1]?.split(/[,\s]+/).map(Number);
      this.m22 = values?.[1] ?? values?.[0] ?? 1;
    }
    if (!Number.isFinite(this.m22)) throw new Error(`Invalid test viewport transform: ${transform}`);
  }
}
Object.defineProperty(window, "DOMMatrixReadOnly", { configurable: true, writable: true, value: TestDOMMatrixReadOnly });
Object.defineProperty(window, "matchMedia", {
  writable: true,
  value: vi.fn().mockImplementation((query: string) => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: vi.fn(),
    removeListener: vi.fn(),
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
    dispatchEvent: vi.fn(),
  })),
});
Object.defineProperty(Element.prototype, "scrollIntoView", { writable: true, value: vi.fn() });
Object.defineProperty(URL, "createObjectURL", { writable: true, value: vi.fn(() => "blob:test") });
Object.defineProperty(URL, "revokeObjectURL", { writable: true, value: vi.fn() });
