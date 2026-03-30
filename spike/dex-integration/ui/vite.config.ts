import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// @ts-expect-error vitest extends the Vite config with a `test` field at runtime
export default defineConfig({
  plugins: [react()],
  test: {
    globals: true,
    environment: "node",
  },
});
