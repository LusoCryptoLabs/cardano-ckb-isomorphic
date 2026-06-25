// cardano_leap_v2.mjs - the Cardano side of the v2 ownership-toggle leap (RGB++-style), as LIB-AGNOSTIC tx
// plans (convert to Lucid/MeshJS/cardano-cli). This is the v2 toggle, NOT the parked mint leg in
// cardano_leap.mjs (leap-in MINT / Groth16). The keystone is the RECIPIENT COMMITMENT folded into the
// owner-signed, Mithril-certified Cardano datum that bound_asset_v2 reads on CKB (docs/RECIPIENT_COMMITMENT.md).
//
// Two directions:
//   LEAP_TO_CKB  (Cardano -> CKB, the dangerous one): the owner SPENDS the seal UTXO at `binding_lock` with the
//     `LeapToCkb { recipient_lock_hash }` redeemer and RE-PARKS the seal in a continuing output whose
//     InlineDatum is LeapSealDatum { owner, commitment = RC, recipient_lock_hash }. binding_lock forces the
//     continuing datum's recipient to equal the redeemer's (length 32) and the owner to sign. RC binds the
//     destination recipient to (state, SOURCE seal); the CKB S5 branch recomputes it and pins the actual lock.
//   LEAP_TO_CARDANO (CKB -> Cardano): mint `seal_prime` one-shot (seal_nft(seed)) at `binding_lock` carrying a
//     2-field SealDatum { owner, commitment = blake2b256(state) } (STATE-ONLY / live parity). The CKB S4 branch
//     names this mint tx as the CardanoBound seal.
//
// RC = blake2b256( state ‖ SOURCE_seal(36 = txid32 ‖ idx u32 LE) ‖ recipient_lock_hash(32) ), PLAIN BLAKE2b-256
// (no personalization) - byte-identical to bound_asset_v2::b2b256. Cross-checked by cardano_leap_v2.test.mjs
// and the Rust host test `cross_language_rc_and_stateonly_vectors`.
import { blake2b } from "@noble/hashes/blake2b";

const strip = (h) => (h || "").replace(/^0x/, "");
const hx = (h) => Uint8Array.from(Buffer.from(strip(h), "hex"));
const hex = (u8) => Buffer.from(u8).toString("hex");
const cat = (...arrs) => { const t = new Uint8Array(arrs.reduce((n, a) => n + a.length, 0)); let o = 0; for (const a of arrs) { t.set(a, o); o += a.length; } return t; };
/** plain BLAKE2b-256 over the concatenated byte parts (matches the CKB verifier's b2b256). */
export const b2b256 = (...parts) => "0x" + hex(blake2b(cat(...parts), { dkLen: 32 }));

/** SOURCE seal as the 36-byte (txid ‖ idx u32 LE) buffer the CKB cell + RC use. */
export function sealOutpoint36(txHashHex, index) {
  const t = hx(txHashHex);
  if (t.length !== 32) throw new Error("seal txHash must be 32 bytes");
  const idx = new Uint8Array(4); new DataView(idx.buffer).setUint32(0, index >>> 0, true); // LE
  return cat(t, idx);
}

/** RC = blake2b256(state ‖ SOURCE seal(36) ‖ recipient_lock_hash(32)). The S5 keystone. */
export function recipientCommitment({ stateHex, sealTxHashHex, sealIndex, recipientLockHashHex }) {
  const r = hx(recipientLockHashHex);
  if (r.length !== 32) throw new Error("recipient_lock_hash must be 32 bytes");
  return b2b256(hx(stateHex), sealOutpoint36(sealTxHashHex, sealIndex), r);
}

/** state-only commitment = blake2b256(state). Used by genesis / transition / leap-to-cardano (live parity). */
export const stateCommitment = (stateHex) => b2b256(hx(stateHex));

/**
 * LEAP_TO_CKB plan: spend the seal at binding_lock with LeapToCkb, re-park it with the RC-bearing datum.
 * @param sealUtxo {txHash,index} the current seal UTXO at binding_lock (the CardanoBound cell's seal on CKB).
 */
export function buildLeapToCkbPlan({ bindingScriptAddr, sealUtxo, sealUnit, ownerCredHex, stateHex, recipientLockHashHex }) {
  if (hx(recipientLockHashHex).length !== 32) throw new Error("recipient_lock_hash must be 32 bytes");
  const rc = recipientCommitment({ stateHex, sealTxHashHex: sealUtxo.txHash, sealIndex: sealUtxo.index, recipientLockHashHex });
  return {
    direction: "leap_to_ckb",
    inputs: [{ ...sealUtxo, redeemer: { constructor: "LeapToCkb", recipient_lock_hash: recipientLockHashHex } }],
    outputs: [{
      address: bindingScriptAddr,
      assets: [{ unit: sealUnit, quantity: "1" }],                  // the seal is RE-PARKED (CKB S5 needs seal_at_lock==true)
      inlineDatum: { type: "LeapSealDatum", owner: ownerCredHex, commitment: rc, recipient_lock_hash: recipientLockHashHex },
    }],
    requiredSigners: [ownerCredHex],                                // binding_lock checks the owner signed
    commitment: rc,
    notes: "convert to Lucid/MeshJS: spend seal w/ LeapToCkb redeemer, re-park output (seal+3-field datum), owner-sign. " +
           "The CKB relayer then certifies THIS tx and runs the S5 leap binding the recipient.",
  };
}

/**
 * LEAP_TO_CARDANO plan: mint seal_prime one-shot at binding_lock with the 2-field state-only datum.
 * @param seedUtxo a unique UTXO the policy consumes (seal_nft(seed)) so the asset name is one-shot.
 */
export function buildSealPrimeMintPlan({ bindingScriptAddr, sealUnit, sealPolicyId, sealAssetName, ownerCredHex, stateHex, seedUtxo }) {
  const commitment = stateCommitment(stateHex);
  return {
    direction: "leap_to_cardano",
    mint: [{ policyId: sealPolicyId, assetName: sealAssetName, quantity: "1", redeemer: { constructor: "SealPrime", seed: seedUtxo } }],
    inputs: [seedUtxo],                                             // consumed so the mint is one-shot
    outputs: [{
      address: bindingScriptAddr,
      assets: [{ unit: sealUnit, quantity: "1" }],
      inlineDatum: { type: "SealDatum", owner: ownerCredHex, commitment },
    }],
    requiredSigners: [ownerCredHex],
    commitment,
    notes: "convert to Lucid/MeshJS: mint seal_prime(seed) one-shot, send to binding_lock with the 2-field datum. " +
           "The CKB S4 branch names THIS mint tx as the CardanoBound seal; state-only commitment = blake2b256(state).",
  };
}
