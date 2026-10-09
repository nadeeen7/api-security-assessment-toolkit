import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

// The SPA never talks to the Flask API cross-origin. In development Vite proxies
// /api to the loopback API, so the browser sees one origin and the API's
// same-origin guard stays satisfied.
const API_TARGET = "http://127.0.0.1:5055";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    // Loopback only, matching the safety model of the API and the lab.
    host: "127.0.0.1",
    port: 5173,
    strictPort: true,
    proxy: {
      "/api": { target: API_TARGET, changeOrigin: true },
    },
  },
  build: {
    outDir: "dist",
    emptyOutDir: true,
  },
});
