import { defineConfig } from "vite";
import { resolve } from "path";

export default defineConfig({
  build: {
    outDir: "dist",
    emptyOutDir: false,
    lib: {
      entry: resolve(__dirname, "src/background/serviceWorker.ts"),
      name: "CodeFortBackgroundWorker",
      formats: ["iife"],
      fileName: () => "background.js",
    },
    rollupOptions: {
      output: {
        extend: true,
      },
    },
  },
  define: {
    "process.env.NODE_ENV": JSON.stringify("production"),
  },
});
