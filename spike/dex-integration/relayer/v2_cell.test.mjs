// node --test v2_cell.test.mjs  - verifies the v2 cell layout matches what bound_asset_v2 parses.
import { test } from "node:test";
import assert from "node:assert";
import { encodeV2Cell, decodeV2Cell, TAG, ckbOwnedCellData, cardanoBoundCellData, registryWitness } from "./v2_cell.mjs";

test("v2 cell encodes at the exact byte offsets the verifier reads", () => {
  const cell = encodeV2Cell({ tag: TAG.CKB_OWNED, sealTxid: "0x" + "ab".repeat(32), sealIdx: 0, lockSlot: "0x" + "33".repeat(32), state: "0x" + "ee".repeat(8) });
  const raw = cell.replace(/^0x/, "");
  assert.equal(raw.slice(0, 2), "02", "version [0]");
  assert.equal(raw.slice(2, 4), "02", "tag [1] = CKB_OWNED");
  assert.equal(raw.slice(4, 68), "ab".repeat(32), "seal_txid [2..34]");
  assert.equal(raw.slice(68, 76), "00000000", "seal_idx [34..38] LE");
  assert.equal(raw.slice(76, 140), "33".repeat(32), "lock_slot [38..70]");
  assert.equal(raw.slice(140), "ee".repeat(8), "state [70..]");
});

test("v2 cell round-trips", () => {
  const d = decodeV2Cell(encodeV2Cell({ tag: TAG.CARDANO_BOUND, sealTxid: "0x" + "cd".repeat(32), sealIdx: 7, lockSlot: "0x" + "00".repeat(32), state: "0x1234" }));
  assert.equal(d.tag, TAG.CARDANO_BOUND);
  assert.equal(d.sealTxid, "0x" + "cd".repeat(32));
  assert.equal(d.sealIdx, 7);
  assert.equal(d.state, "0x1234");
});

test("ckbOwnedCellData pins dest seal + recipient slot", () => {
  const d = decodeV2Cell(ckbOwnedCellData({ destTxHash: "0x" + "11".repeat(32), recipientLockHash: "0x" + "22".repeat(32), state: "0x" + "aa".repeat(4) }));
  assert.equal(d.tag, TAG.CKB_OWNED);
  assert.equal(d.sealTxid, "0x" + "11".repeat(32));   // dest seal = certified tx hash
  assert.equal(d.lockSlot, "0x" + "22".repeat(32));   // recipient lock hash
});

test("cardanoBoundCellData zeroes the lock slot", () => {
  const d = decodeV2Cell(cardanoBoundCellData({ sealPrimeTxHash: "0x" + "44".repeat(32), state: "0x99" }));
  assert.equal(d.tag, TAG.CARDANO_BOUND);
  assert.equal(d.lockSlot, "0x" + "00".repeat(32));   // authority moved off-chain to SealDatum.owner
});

test("registry witness is key ‖ 256 siblings (8224 bytes)", () => {
  const sibs = Array.from({ length: 256 }, (_, i) => "0x" + i.toString(16).padStart(2, "0").repeat(32));
  const w = registryWitness("0x" + "77".repeat(32), sibs);
  assert.equal((w.length - 2) / 2, 32 + 256 * 32);    // 8224 bytes
  assert.equal(w.replace(/^0x/, "").slice(0, 64), "77".repeat(32));
});

test("CROSS-LANGUAGE vector: byte-identical to the bound_asset_v2 Rust host test", () => {
  // The same fixed (tag, seal, idx, lock, state) must encode identically off-chain (here) and on-chain
  // (bound_asset_v2.rs::tests::layout_vector_matches_offchain_builder). If these diverge, the builder emits
  // cells the verifier won't parse.
  const expected = "0x0202" + "ab".repeat(32) + "00000000" + "33".repeat(32) + "ee".repeat(8);
  assert.equal(encodeV2Cell({ tag: TAG.CKB_OWNED, sealTxid: "0x" + "ab".repeat(32), sealIdx: 0, lockSlot: "0x" + "33".repeat(32), state: "0x" + "ee".repeat(8) }), expected);
});

test("rejects bad tag, short txid, wrong sibling count", () => {
  assert.throws(() => encodeV2Cell({ tag: 0x03, sealTxid: "0x" + "00".repeat(32) }));
  assert.throws(() => encodeV2Cell({ tag: TAG.CKB_OWNED, sealTxid: "0x00" }));
  assert.throws(() => registryWitness("0x" + "00".repeat(32), ["0x" + "00".repeat(32)]));
  assert.throws(() => decodeV2Cell("0x0101"));        // bad version + too short
});
