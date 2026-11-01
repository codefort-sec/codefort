import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { resolve } from "path";

export default defineConfig({
  plugins: [react()],
  define: {
    "process.env.NODE_ENV": JSON.stringify("production"),
  },
  build: {
    outDir: "dist",
    emptyOutDir: false,
    lib: {
      entry: resolve(__dirname, "src/content/index.tsx"),
      name: "CodeFortGuardContent",
      formats: ["iife"],
      fileName: () => "content.js",
    },
    rollupOptions: {
      output: {
        extend: true,
        assetFileNames: (assetInfo) => {
          if (assetInfo.name && assetInfo.name.endsWith(".css")) {
            return "content.css";
          }
          return "assets/[name]-[hash].[ext]";
        },
      },
    },
  },
});
