import "@testing-library/jest-dom/vitest";
import { cleanup } from "@testing-library/react";
import { afterEach, vi } from "vitest";

afterEach(() => {
  cleanup();
  window.localStorage.clear();
  window.location.hash = "";
  vi.restoreAllMocks();
});

class TestResizeObserver {
  observe() {}
  unobserve() {}
  disconnect() {}
}

Object.defineProperty(globalThis, "ResizeObserver", { writable: true, value: TestResizeObserver });
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
