import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Dev server proxies the relayer proof/witness API (the dApp backend) so the browser can call it same-origin.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": { target: "http://localhost:8799", changeOrigin: true },
    },
  },
});
