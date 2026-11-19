import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { viteSingleFile } from "vite-plugin-singlefile";

// One self-contained index.html (JS + CSS inlined) so dist/ opens from file:// with no
// server and no network. Data comes from public/data/bundles.js (a classic script).
export default defineConfig({
  base: "./",
  plugins: [react(), viteSingleFile()],
  build: { outDir: "dist", emptyOutDir: true, modulePreload: { polyfill: false } },
});
