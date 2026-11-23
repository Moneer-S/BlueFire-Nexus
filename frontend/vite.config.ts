import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  base: "/ui/",
  plugins: [react(), {
    name: "bluefire-normalize-generated-text",
    transformIndexHtml: {
      order: "post",
      handler(html) {
        return html.replace(/\r+\n/g, "\n").replace(/\r/g, "\n").replace(/[ \t]+$/gm, "");
      },
    },
    generateBundle(_options, bundle) {
      for (const output of Object.values(bundle)) {
        if (output.type === "chunk") {
          output.code = output.code.replace(/\r\n?/g, "\n").replace(/[ \t]+$/gm, "");
        } else if (typeof output.source === "string") {
          output.source = output.source.replace(/\r\n?/g, "\n").replace(/[ \t]+$/gm, "");
        }
      }
    },
  }],
  build: {
    outDir: "../bluefire/ui",
    emptyOutDir: true,
    assetsDir: "",
    cssCodeSplit: false,
    sourcemap: false,
    rollupOptions: {
      output: {
        entryFileNames: "app.js",
        chunkFileNames: "chunk-[name]-[hash].js",
        assetFileNames: (asset) => asset.names?.some((name) => name.endsWith(".css")) ? "styles.css" : "[name][extname]",
      },
    },
  },
  server: {
    port: 5173,
    strictPort: true,
  },
});
