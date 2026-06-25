// v2_cell.mjs - PURE encoders for the bound_asset_v2 ownership-toggle leap (no chain deps).
// Layout the verifier parses (spike/burn-gated-unlock/src/bin/bound_asset_v2.rs):
//   v2 cell data = version(1)=0x02 ‖ tag(1) ‖ seal_txid(32) ‖ seal_idx(u32 LE,4) ‖ lock_slot(32) ‖ state(var)
//   tag ∈ { CARDANO_BOUND=0x01, CKB_OWNED=0x02 }
//   registry witness (input_type) = key(32) ‖ 256 × sibling(32)
// The leap-in cert witness is the SAME MMR-proof bytes as the FINALIZE witness (mithril_proof.mjs).

export const VERSION = 0x02;
export const TAG = { CARDANO_BOUND: 0x01, CKB_OWNED: 0x02 };
const ZERO32 = "0x" + "00".repeat(32);

function hexToBytes(h) { const s = (h ?? "").replace(/^0x/, ""); const o = new Uint8Array(s.length / 2); for (let i = 0; i < o.length; i++) o[i] = parseInt(s.slice(2 * i, 2 * i + 2), 16); return o; }
function bytesToHex(b) { return "0x" + Array.from(b, (x) => x.toString(16).padStart(2, "0")).join(""); }
const u32le = (n) => { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n, true); return b; };

/** Encode a v2 bound cell. `state` may be a 0x-hex string or a byte array. Returns 0x-hex. */
export function encodeV2Cell({ tag, sealTxid, sealIdx = 0, lockSlot = ZERO32, state = "0x" }) {
  if (tag !== TAG.CARDANO_BOUND && tag !== TAG.CKB_OWNED) throw new Error("bad tag (must be 0x01 or 0x02)");
  const txid = hexToBytes(sealTxid); if (txid.length !== 32) throw new Error("seal_txid must be 32 bytes");
  const slot = hexToBytes(lockSlot); if (slot.length !== 32) throw new Error("lock_slot must be 32 bytes");
  const st = typeof state === "string" ? hexToBytes(state) : Uint8Array.from(state);
  const out = new Uint8Array(70 + st.length);
  out[0] = VERSION; out[1] = tag; out.set(txid, 2); out.set(u32le(sealIdx), 34); out.set(slot, 38); out.set(st, 70);
  return bytesToHex(out);
}
export function decodeV2Cell(hex) {
  const b = hexToBytes(hex); if (b.length < 70) throw new Error("cell < 70 bytes");
  if (b[0] !== VERSION) throw new Error(`bad version 0x${b[0].toString(16)} (expected 0x02)`);
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  return { version: b[0], tag: b[1], sealTxid: bytesToHex(b.slice(2, 34)), sealIdx: dv.getUint32(34, true), lockSlot: bytesToHex(b.slice(38, 70)), state: bytesToHex(b.slice(70)) };
}

/** The CkbOwned cell a LEAP_TO_CKB produces: dest seal = the certified tx hash; lock slot = the owner-chosen
 *  recipient lock-script hash (the verifier pins both the slot AND the actual on-chain lock to it - B3). */
export function ckbOwnedCellData({ destTxHash, recipientLockHash, state = "0x" }) {
  return encodeV2Cell({ tag: TAG.CKB_OWNED, sealTxid: destTxHash, sealIdx: 0, lockSlot: recipientLockHash, state });
}
/** The CardanoBound cell a LEAP_TO_CARDANO produces: seal = the seal_prime mint tx hash; lock slot = zero
 *  (authority is now SealDatum.owner on Cardano). */
export function cardanoBoundCellData({ sealPrimeTxHash, state = "0x" }) {
  return encodeV2Cell({ tag: TAG.CARDANO_BOUND, sealTxid: sealPrimeTxHash, sealIdx: 0, lockSlot: ZERO32, state });
}

/** registry witness = key(32) ‖ 256 × sibling(32). `siblings` is an array of 256 0x-hex 32-byte values. */
export function registryWitness(key, siblings) {
  const k = hexToBytes(key); if (k.length !== 32) throw new Error("key must be 32 bytes");
  if (!Array.isArray(siblings) || siblings.length !== 256) throw new Error("need exactly 256 siblings");
  const out = new Uint8Array(32 + 256 * 32); out.set(k, 0);
  siblings.forEach((s, i) => { const sb = hexToBytes(s); if (sb.length !== 32) throw new Error("each sibling must be 32 bytes"); out.set(sb, 32 + i * 32); });
  return bytesToHex(out);
}
