// deploy_v2.smoke.mjs — pure-logic checks for the v2 deploy wiring (no chain, no key). Validates the SMT
// empty-root constant, the immutable code-hash derivation (ccc.hashCkb), and the cell-dep block assembly.
import { test } from "node:test";
import assert from "node:assert";
import { EMPTY_SMT_ROOT, dataCodeHash, leapCellDeps, deriveCodeHashes } from "./deploy_v2.mjs";

test("empty SMT root is a 32-byte hex (matches registry::empty_root)", () => {
  assert.match(EMPTY_SMT_ROOT, /^0x[0-9a-f]{64}$/);
});

test("dataCodeHash == CKB's well-known empty ckbhash (proves we use ckb-default-hash, data1)", () => {
  assert.equal(dataCodeHash(new Uint8Array()), "0x44f4c69744d5f8c55d642062949dcae49bc4e7ef43d388c5a12f42b5633d163e");
});

test("registry binary's immutable code hash is stable (no option_env => deterministic)", () => {
  const h = deriveCodeHashes();
  assert.equal(h.registryCodeHash, "0x8b3c821b7a332dd424e00ae2204c4f07950b05ed64fd6987f661755fbd3f5177");
  assert.ok(h.boundBytes > 0 && h.registryBytes > 0);
});

test("leapCellDeps assembles the four-piece dep block", () => {
  const d = leapCellDeps({ boundCodeOutPoint: "B", registryCodeOutPoint: "RC", registryStateOutPoint: "RS", checkpointOutPoint: "C" });
  assert.deepEqual(d, { boundCode: "B", registryCode: "RC", registryState: "RS", checkpoint: "C" });
});
