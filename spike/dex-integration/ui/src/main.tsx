import React from "react";
import { createRoot } from "react-dom/client";
import { ccc } from "@ckb-ccc/connector-react";
import { App } from "./App";
import "./styles.css";

const root = createRoot(document.getElementById("root")!);
root.render(
  <React.StrictMode>
    {/* CCC provides the JoyID (and other CKB wallet) connect flow + a shared client */}
    <ccc.Provider name="Bridged Token DEX">
      <App />
    </ccc.Provider>
  </React.StrictMode>,
);
