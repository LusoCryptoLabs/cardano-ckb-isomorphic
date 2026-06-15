// cardano.js — CIP-30 wallet connect (Lace, Eternl, Nami, Typhon, ...). Self-custody: the user signs every
// transaction; we only read the connected address + network here. Tx building/signing lands in increment 4.

export const shortHex = (h, head = 14, tail = 8) => {
  if (!h) return "—";
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
  return { api, key, name: provider.name || key, icon: provider.icon, networkId, addressHex };
}
