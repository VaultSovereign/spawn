import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

const packageRoot = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(packageRoot, "../..");

export default defineConfig({
  plugins: [
    react(),
  ],
  server: {
    fs: {
      allow: [
        repoRoot,
      ],
    },
  },
});
