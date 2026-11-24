import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";
import { shippedSummariesPlugin } from "./shipped-summaries";

export default defineConfig({
  plugins: [react(), shippedSummariesPlugin()],
  // The demo build's client reads the recording that ships with the service.
  server: { fs: { allow: [".", "../bluefire/data/recordings"] } },
  test: {
    environment: "jsdom",
    setupFiles: ["./tests/setup.ts"],
    css: true,
    exclude: ["tests/e2e/**", "tests/service/**", "**/node_modules/**", "**/dist/**"],
  },
});
