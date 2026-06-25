// cardano.js - CIP-30 wallet connect (Lace, Eternl, Nami, Typhon, ...). Self-custody: the user signs every
// transaction; we only read the connected address + network here. Tx building/signing lands in increment 4.

export const shortHex = (h, head = 14, tail = 8) => {
  if (!h) return "-";
  const s = String(h);
  return s.length > head + tail + 1 ? `${s.slice(0, head)}…${s.slice(-tail)}` : s;
};

// CIP-30 providers inject under window.cardano.<key> with { enable, apiVersion, name, icon }.
export function listCardanoWallets() {
  const w = typeof window !== "undefined" ? window.cardano || {} : {};
  return Object.keys(w)
    .filter((k) => w[k] && typeof w[k].enable === "function" && w[k].apiVersion)
    .map((k) => ({ key: k, name: w[k].name || k, icon: w[k].icon }));
}

const STORE = "chiral.cardano.wallet";

export async function connectCardano(key) {
  const provider = window.cardano?.[key];
  if (!provider) throw new Error("wallet not found: " + key);
  const api = await provider.enable(); // user approves the connection in their wallet
  const networkId = await api.getNetworkId(); // 0 = testnet (preview/preprod), 1 = mainnet
  let addressHex = null;
  for (const get of [() => api.getUsedAddresses(), () => api.getUnusedAddresses()]) {
    try { const a = await get(); if (a && a.length) { addressHex = a[0]; break; } } catch { /* keep trying */ }
  }
  if (!addressHex) { try { addressHex = await api.getChangeAddress(); } catch { /* ignore */ } }
  try { localStorage.setItem(STORE, key); } catch { /* private mode */ }   // remember for auto-reconnect
  return { api, key, name: provider.name || key, icon: provider.icon, networkId, addressHex };
}

// Auto-reconnect on page load: re-enable the last-used wallet WITHOUT a popup if the dApp is still
// authorized (CIP-30 `isEnabled()`). Wallet extensions inject window.cardano asynchronously, so poll briefly.
export async function reconnectCardano(tries = 24, gapMs = 250) {
  let key; try { key = localStorage.getItem(STORE); } catch { return null; }
  if (!key) return null;
  for (let i = 0; i < tries; i++) {
    const provider = window.cardano?.[key];
    if (provider) {
      // keep retrying isEnabled - some wallets report false for a moment right after injecting.
      try { if (await provider.isEnabled()) return await connectCardano(key); } catch { /* retry */ }
    }
    await new Promise((r) => setTimeout(r, gapMs));   // wait for the extension to inject / settle
  }
  return null;   // remembered but not silently authorizable - the UI offers a one-click reconnect
}

// The last-used wallet (if any) so the UI can offer a single-click "Reconnect <name>" instead of re-picking.
export function rememberedWallet() {
  let key; try { key = localStorage.getItem(STORE); } catch { return null; }
  if (!key) return null;
  const w = typeof window !== "undefined" ? window.cardano?.[key] : null;
  return { key, name: w?.name || key, icon: w?.icon, present: !!w };
}

export function forgetCardano() { try { localStorage.removeItem(STORE); } catch { /* ignore */ } }
