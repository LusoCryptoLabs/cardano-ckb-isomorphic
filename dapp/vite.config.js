import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import wasm from "vite-plugin-wasm";
import topLevelAwait from "vite-plugin-top-level-await";
import { nodePolyfills } from "vite-plugin-node-polyfills";

// Dev server proxies the relayer proof/witness API (the dApp backend) so the browser can call it same-origin.
// wasm + top-level-await are required by Lucid (cardano-multiplatform-lib ships as WASM); nodePolyfills supplies
// the node built-ins (events/stream/Buffer/global/process) that ccc + Lucid's deps (readable-stream, etc.)
// need - without it the browser hits "Class extends value undefined" (EventEmitter) and renders blank.
export default defineConfig({
  plugins: [nodePolyfills(), wasm(), topLevelAwait(), react()],
  // @harmoniclabs/cbor (via Lucid) is CJS with circular deps; strictRequires wraps every require so the
  // base class isn't `undefined` when a subclass extends it ("Class extends value undefined"). esnext target
  // avoids class-hoisting TDZ issues from down-leveling.
  build: {
    target: "esnext",
    commonjsOptions: { transformMixedEsModules: true, strictRequires: true },
    // Split the big, rarely-changing vendors into their own immutable chunks so an app-code change doesn't
    // bust the heavy dependencies in the browser cache (paired with server.mjs's `immutable` headers).
    // Lucid is a lazy dynamic import (mint.js/xada.js), so its chunk loads only on the first wallet action.
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (!id.includes("node_modules")) return;
          if (/@lucid-evolution|@harmoniclabs|@anastasia-labs|lucid-cardano/.test(id)) return "lucid";
          if (/@ckb-ccc|@ckb-lumos|@nervosnetwork/.test(id)) return "ckb";
          if (/[\\/]node_modules[\\/](react|react-dom|scheduler)[\\/]/.test(id)) return "react-vendor";
        },
      },
    },
  },
  optimizeDeps: { esbuildOptions: { target: "esnext" } },
  server: {
    port: 5173,
    proxy: {
      "/api": { target: "http://localhost:8799", changeOrigin: true },
    },
  },
});
