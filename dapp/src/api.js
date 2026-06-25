// api.js - access-token plumbing for the gated heavy endpoints.
//
// The relayer's prove/mint/release/return endpoints are expensive (a Groth16 prove on demand), so on the VPS
// they're gated by CHIRAL_ACCESS_TOKEN. The operator shares a tester link carrying the token (?t=… or #t=…);
// we persist it on first load and attach it to heavy API calls as the x-chiral-access header. Open endpoints
// (config/health/job) need no token, so the page always loads - only the work-triggering calls are gated.
const KEY = "chiral.access";

// Call once at startup: lift a token out of the URL (query or hash) into localStorage, then tidy the URL.
export function captureAccessToken() {
  try {
    const u = new URL(location.href);
    const fromHash = new URLSearchParams((location.hash || "").replace(/^#/, "")).get("t");
    const t = u.searchParams.get("t") || fromHash;
    if (t) {
      localStorage.setItem(KEY, t);
      // strip it from the visible URL so the token isn't shoulder-surfed / copied around
      u.searchParams.delete("t");
      const clean = u.pathname + (u.searchParams.toString() ? "?" + u.searchParams.toString() : "");
      history.replaceState(null, "", clean);
    }
  } catch { /* no URL/storage - stay open (dev) */ }
}

export function accessToken() { try { return localStorage.getItem(KEY) || ""; } catch { return ""; } }

// headers for a JSON POST to a heavy endpoint: content-type + the access token when we have one.
export function jsonHeaders() {
  const h = { "content-type": "application/json" };
  const t = accessToken();
  if (t) h["x-chiral-access"] = t;
  return h;
}
