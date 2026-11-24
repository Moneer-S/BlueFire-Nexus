// Builds the single replay page: one self-contained file, bluefire/ui/replay.html,
// with its script, styles and font inlined and nothing fetched. Its recording
// element holds null; a recording is put into it to make a replay.
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { viteSingleFile } from "vite-plugin-singlefile";

export default defineConfig({
  base: "./",
  publicDir: false,
  plugins: [react(), viteSingleFile({ removeViteModuleLoader: true })],
  build: {
    outDir: "../bluefire/ui",
    emptyOutDir: false,
    sourcemap: false,
    rollupOptions: { input: "replay.html" },
  },
});
