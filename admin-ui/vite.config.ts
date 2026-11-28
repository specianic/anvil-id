import path from "node:path";
import { fileURLToPath } from "node:url";
import tailwindcss from "@tailwindcss/vite";
import { tanstackRouter } from "@tanstack/router-plugin/vite";
import react from "@vitejs/plugin-react";
import { defineConfig, searchForWorkspaceRoot } from "vite";

const root = path.dirname(fileURLToPath(import.meta.url));

// The console is served by anvilid at /console/* (03-22). In development the API and the OIDC
// endpoints of the system tenant are proxied to a local `anvilid serve`.
export default defineConfig({
  base: "/console/",
  plugins: [
    // Must run before the React plugin so generated route trees are transformed.
    tanstackRouter({ target: "react", autoCodeSplitting: true }),
    react(),
    tailwindcss(),
  ],
  resolve: {
    alias: { "@": path.resolve(root, "src") },
  },
  server: {
    // src/fonts.css loads the end-user theme's self-hosted fonts from the repository's themes dir.
    fs: { allow: [searchForWorkspaceRoot(root), path.resolve(root, "../themes/default/static/fonts")] },
    proxy: {
      "/api": "http://localhost:8080",
      "/t": "http://localhost:8080",
    },
  },
  build: {
    outDir: "dist",
    emptyOutDir: true,
    sourcemap: false,
  },
});
