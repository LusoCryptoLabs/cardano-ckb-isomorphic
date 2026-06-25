// cardano_leap.mjs - build the Cardano leap-IN MINT (the wrapped-FT mint via `leap_mint_guard`), as a
// LIB-AGNOSTIC transaction plan (same approach as cardano_cip68.mjs - convert to Lucid/MeshJS/cardano-cli).
//
// The validator (validators/leap_mint_guard.ak) checks, for redeemer LeapInMint:
//   • the tx mints exactly one asset name under the FT policy (`only_one_name`);
//   • a `cardano_bound` OUTPUT is present whose InlineDatum BoundState{ ckb_seal, state } encodes
//     state = amount(16 LE) ‖ recipient_credential(28) - `cardano_bound` itself verifies the Groth16 proof
//     of the CKB lock that authenticates the leap;
//   • the live admin policy (caps/pause) read from a REFERENCE INPUT permits it (`enforce_policy`);
//   • minted == amount AND all of it goes to `recipient` (`authorize_mint`).
// So the plan below mints `amount` of the FT to the recipient, carries the bound output, and references the
// policy cell. The Groth16 proof rides in `cardano_bound`'s redeemer (its own validator), supplied by the prover.

const U128_MAX = (1n << 128n) - 1n;
const utf8hex = (s) => Array.from(new TextEncoder().encode(s), (b) => b.toString(16).padStart(2, "0")).join("");

/** state = amount(16 LE) ‖ recipient_credential(28), as the guard slices it (bytearray_to_integer False). */
export function encodeBoundState(amount, recipientCredHex) {
  if (typeof amount !== "bigint" || amount < 0n || amount > U128_MAX) throw new Error("amount out of u128 range");
  const cred = recipientCredHex.replace(/^0x/, "");
  if (cred.length !== 56) throw new Error("recipient credential must be 28 bytes");
  let hex = "";
  for (let i = 0; i < 16; i++) { hex += Number((amount >> BigInt(8 * i)) & 0xffn).toString(16).padStart(2, "0"); }
  return hex + cred; // 16 + 28 = 44 bytes
}

/** full FT asset name = (333) label ‖ utf8(name). */
export const ftAssetName = (ftNameAscii, ftLabelHex = "0014df10") => ftLabelHex + utf8hex(ftNameAscii);

/**
 * A lib-agnostic plan for the leap-in FT mint. Feed to your Cardano tx lib: set the mint + redeemer, attach
 * the policy reference input, build the bound output (its datum) and the recipient FT output, attach the
 * `cardano_bound` spend/redeemer carrying `groth16Proof`, then balance/sign with the relayer key.
 */
export function buildLeapInMintPlan({ policyId, ftNameAscii, amount, recipientAddr, recipientCredHex, ckbSealHex, boundScriptAddr, policyRefUtxo, groth16Proof }) {
  if (typeof amount !== "bigint" || amount <= 0n) throw new Error("amount must be a positive BigInt");
  const assetName = ftAssetName(ftNameAscii);
  const unit = policyId.replace(/^0x/, "") + assetName;
  return {
    mint: [{ policyId, assetName, quantity: amount.toString(), redeemer: "LeapInMint" }],
    referenceInputs: [policyRefUtxo], // the chiral_policy cell (caps/pause), read not spent
    outputs: [
      // the cardano_bound output the guard reads (its validator verifies the Groth16 proof)
      { address: boundScriptAddr, inlineDatum: { type: "BoundState", ckb_seal: ckbSealHex, state: encodeBoundState(amount, recipientCredHex) } },
      // the minted FT, straight to the recipient
      { address: recipientAddr, assets: [{ unit, quantity: amount.toString() }] },
    ],
    // the proof for cardano_bound's own redeemer (the { vk, proof, public_inputs } fixture from the prover)
    boundRedeemer: { groth16Proof: groth16Proof ?? null },
    notes: "convert to Lucid/MeshJS: mint+redeemer, ref input, the two outputs, cardano_bound spend w/ proof, then balance+sign with RELAYER_CARDANO_KEY",
  };
}
