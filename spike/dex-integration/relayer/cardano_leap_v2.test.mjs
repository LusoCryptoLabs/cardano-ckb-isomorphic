// cardano_leap_v2.test.mjs - the Cardano v2 leap builders. The headline checks are the CROSS-LANGUAGE
// commitment vectors: RC and the state-only commitment must be byte-identical to bound_asset_v2::b2b256
// (Rust host test `cross_language_rc_and_stateonly_vectors`), or the certified datum won't satisfy the verifier.
import { test } from "node:test";
import assert from "node:assert";
import { recipientCommitment, stateCommitment, sealOutpoint36, buildLeapToCkbPlan, buildSealPrimeMintPlan } from "./cardano_leap_v2.mjs";

const STATE = "0x6c6561702d64656d6f2d7374617465";   // "leap-demo-state"
const SEAL_TX = "0x" + "ab".repeat(32);
const RECIP = "0x" + "33".repeat(32);

test("RC matches the Rust verifier's cross-language vector", () => {
  const rc = recipientCommitment({ stateHex: STATE, sealTxHashHex: SEAL_TX, sealIndex: 0, recipientLockHashHex: RECIP });
  assert.equal(rc, "0xc08948bc1439930d9007793543b88abf866d712e2f9cbccce3c7fea86775fbc7");
});

test("state-only commitment matches the Rust cross-language vector", () => {
  assert.equal(stateCommitment("0x6c6561702d6f75742d7374617465"), "0x10f5119872cc031eba985be57ac53ab22972c1b25066edb31932aa6d2c21c092");
});

test("sealOutpoint36 is txid(32) ‖ idx(u32 LE)", () => {
  const s = Buffer.from(sealOutpoint36(SEAL_TX, 1)).toString("hex");
  assert.equal(s, "ab".repeat(32) + "01000000");
});

test("leap_to_ckb plan re-parks the seal and carries the 3-field RC datum", () => {
  const p = buildLeapToCkbPlan({ bindingScriptAddr: "addr_test1binding", sealUtxo: { txHash: SEAL_TX, index: 0 }, sealUnit: "polid.SEAL", ownerCredHex: "0x" + "0b".repeat(28), stateHex: STATE, recipientLockHashHex: RECIP });
  assert.equal(p.direction, "leap_to_ckb");
  assert.equal(p.inputs[0].redeemer.constructor, "LeapToCkb");
  assert.equal(p.inputs[0].redeemer.recipient_lock_hash, RECIP);
  assert.equal(p.outputs[0].inlineDatum.recipient_lock_hash, RECIP);
  assert.equal(p.outputs[0].inlineDatum.commitment, "0xc08948bc1439930d9007793543b88abf866d712e2f9cbccce3c7fea86775fbc7");
  assert.equal(p.outputs[0].assets[0].quantity, "1");             // seal re-parked (CKB S5 seal_at_lock==true)
  assert.deepEqual(p.requiredSigners, ["0x" + "0b".repeat(28)]);
});

test("leap_to_ckb rejects a non-32-byte recipient", () => {
  assert.throws(() => buildLeapToCkbPlan({ bindingScriptAddr: "a", sealUtxo: { txHash: SEAL_TX, index: 0 }, sealUnit: "u", ownerCredHex: "0x00", stateHex: STATE, recipientLockHashHex: "0x33" }));
});

test("seal_prime mint plan carries the 2-field state-only datum", () => {
  const p = buildSealPrimeMintPlan({ bindingScriptAddr: "addr_test1binding", sealUnit: "polid.SEAL", sealPolicyId: "polid", sealAssetName: "SEAL", ownerCredHex: "0x" + "0b".repeat(28), stateHex: "0x6c6561702d6f75742d7374617465", seedUtxo: { txHash: "0x" + "cd".repeat(32), index: 2 } });
  assert.equal(p.direction, "leap_to_cardano");
  assert.equal(p.mint[0].redeemer.constructor, "SealPrime");
  assert.equal(p.outputs[0].inlineDatum.type, "SealDatum");
  assert.equal(p.outputs[0].inlineDatum.commitment, "0x10f5119872cc031eba985be57ac53ab22972c1b25066edb31932aa6d2c21c092");
  assert.equal(p.inputs[0].index, 2);                              // the one-shot seed is consumed
});
