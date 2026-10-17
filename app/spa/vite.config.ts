import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

// The edge CSP is default-src 'self' (no inline script or style): no
// modulepreload polyfill (an inline script), compiled CSS only.
export default defineConfig({
  plugins: [react(), tailwindcss()],
  build: {
    target: "es2022",
    sourcemap: false,
    modulePreload: { polyfill: false },
    assetsInlineLimit: 0,
  },
  server: {
    port: 5173,
    proxy: {
      "/api": { target: "http://localhost:3000", rewrite: (p) => p.replace(/^\/api/, "") },
    },
  },
});
