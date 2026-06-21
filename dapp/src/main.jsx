import React from "react";
import { createRoot } from "react-dom/client";
import App from "./App.jsx";
import { captureAccessToken } from "./api.js";

captureAccessToken();   // lift a tester-link ?t=… / #t=… token into storage before the app makes any API call

createRoot(document.getElementById("root")).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
