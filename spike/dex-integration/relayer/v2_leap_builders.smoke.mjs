// Smoke test for the v2 leap tx assemblers: assert the assembled tx structure + the embedded v2 cell data.
// Run with @ckb-ccc/core resolvable (a node_modules junction).  node v2_leap_builders.smoke.mjs
import assert from "node:assert";
import { ccc } from "@ckb-ccc/core";
import { assembleLeapToCkb, assembleLeapToCardano } from "./v2_leap_builders.mjs";
import { decodeV2Cell, TAG } from "./v2_cell.mjs";

const script = (args) => ccc.Script.from({ codeHash: "0x" + "11".repeat(32), hashType: "type", args });
const op = (i) => ccc.OutPoint.from({ txHash: "0x" + "22".repeat(32), index: i });
const cell = (data, lock, type) => ({ outPoint: op(0), cellOutput: ccc.CellOutput.from({ capacity: 2000000000000n, lock, type }), outputData: data });

const boundType = script("0xaa");
const recipientLock = script("0xbb");
const deps = { checkpoint: op(1), boundCode: op(2), registryCode: op(3) };

// ---- S5 LEAP_TO_CKB ----
const tx5 = assembleLeapToCkb({
  boundCell: cell("0x", script("0xc0"), boundType),
  registryCell: cell("0x" + "00".repeat(32), script("0xc1"), script("0xc2")),
  recipientLock, state: "0x" + "ee".repeat(4), destTxHash: "0x" + "33".repeat(32),
  certWitness: new Uint8Array([1, 2, 3]), registryWitness: new Uint8Array(8224), registryNewRoot: "0x" + "44".repeat(32), deps,
});
assert.equal(tx5.inputs.length, 2, "S5: bound + registry inputs");
assert.equal(tx5.outputs.length, 2, "S5: ckbOwned + registry outputs");
const owned = decodeV2Cell(tx5.outputsData[0]);
assert.equal(owned.tag, TAG.CKB_OWNED);
assert.equal(owned.sealTxid, "0x" + "33".repeat(32), "dest seal = certified tx hash");
assert.equal(owned.lockSlot, ccc.Script.from(recipientLock).hash(), "lock slot pinned to recipient hash");
assert.equal(tx5.outputsData[1], "0x" + "44".repeat(32), "continuing registry root");
assert.equal(tx5.cellDeps.length, 3, "S5: checkpoint + bound + registry deps");
assert.ok(tx5.witnesses[0].length > 2 && tx5.witnesses[1].length > 2, "both witnesses set");

// ---- S4 LEAP_TO_CARDANO ----
const tx4 = assembleLeapToCardano({
  boundCell: cell("0x", script("0xd0"), boundType), state: "0x99", sealPrimeTxHash: "0x" + "55".repeat(32),
  certWitness: new Uint8Array([9]), deps,
});
assert.equal(tx4.inputs.length, 1, "S4: single CkbOwned input (no nullifier)");
const cb = decodeV2Cell(tx4.outputsData[0]);
assert.equal(cb.tag, TAG.CARDANO_BOUND);
assert.equal(cb.sealTxid, "0x" + "55".repeat(32), "seal = seal_prime mint tx hash");
assert.equal(cb.lockSlot, "0x" + "00".repeat(32), "lock slot zeroed (authority off-chain)");
assert.equal(tx4.cellDeps.length, 2, "S4: checkpoint + bound deps");

console.log("v2 leap builders smoke: ALL OK (S5 + S4 structure + embedded cell data verified)");
