// amount.ts - the canonical value encoding, ported 1:1 from guard/MAPPING_SPEC.md and leap-guard-core.
// ONE integer encoding on the value path: u128 BASE UNITS, little-endian, exactly 16 bytes. Decimals are
// display-only metadata (immutable). There is NO float and NO rounding/truncating step here.

import { TOKEN } from "../config";

export const U128_MAX = (1n << 128n) - 1n;

/** display decimal STRING -> base-units BigInt. Rejects floats, excess precision, and out-of-range. */
export function toBaseUnits(displayAmount: string, decimals: number = TOKEN.decimals): bigint {
  const s = displayAmount.trim();
  if (!/^\d+(\.\d+)?$/.test(s)) throw new Error("amount must be a non-negative decimal string");
  const [whole, frac = ""] = s.split(".");
  if (frac.length > decimals) throw new Error(`too many decimal places (max ${decimals})`);
  const v = BigInt(whole + frac.padEnd(decimals, "0"));
  if (v < 0n || v > U128_MAX) throw new Error("amount out of u128 range");
  return v;
}

/** base-units BigInt -> display string (UI only: base / 10^decimals). Never used in on-chain math. */
export function fromBaseUnits(base: bigint, decimals: number = TOKEN.decimals): string {
  const neg = base < 0n;
  const v = neg ? -base : base;
  const d = 10n ** BigInt(decimals);
  const whole = v / d;
  const frac = (v % d).toString().padStart(decimals, "0").replace(/0+$/, "");
  return (neg ? "-" : "") + whole.toString() + (frac ? "." + frac : "");
}

/** canonical 16-byte LE encoding of a u128 amount (matches encode_amount_le / u128le on-chain). */
export function u128le(v: bigint): Uint8Array {
  if (v < 0n || v > U128_MAX) throw new Error("amount out of u128 range");
  const b = new Uint8Array(16);
  for (let i = 0; i < 16; i++) b[i] = Number((v >> BigInt(8 * i)) & 0xffn);
  return b;
}

/** decode the amount (first 16 bytes, LE) from a state/cell-data byte array (matches decode_amount_le). */
export function decodeU128le(bytes: Uint8Array): bigint {
  if (bytes.length < 16) throw new Error("state too short for a u128 amount");
  let v = 0n;
  for (let i = 15; i >= 0; i--) v = (v << 8n) | BigInt(bytes[i]);
  return v;
}

// ---- hex helpers (no Buffer; browser-safe) ----
export const utf8ToHex = (s: string): string =>
  Array.from(new TextEncoder().encode(s), (b) => b.toString(16).padStart(2, "0")).join("");

export const hexToBytes = (hex: string): Uint8Array => {
  const h = hex.replace(/^0x/, "");
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return out;
};

export const bytesToHex = (b: Uint8Array): string =>
  Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
