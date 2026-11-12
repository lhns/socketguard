import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  clearScreen: false,
  test: {
    environment: "jsdom",
    setupFiles: ["./src/test/setup.ts"],
    // The suite runs in parallel jsdom workers, and a test drives a whole page.
    testTimeout: 15_000,
  },
  server: {
    port: 5173,
    strictPort: true,
  },
});
