// verify_toggle.mjs - confirm the FULL toggle's terminal on-chain state on Pudge.
import { ccc } from "@ckb-ccc/core";
const client = new ccc.ClientPublicTestnet();
const S5 = "0xb45812da24a0824de6cab1e38d18fef4e46a9adee57414018f2aa6a4201cf62f";
const live = async (op) => !!(await client.getCellLive(op, true).catch(() => null));
const cell = async (op) => await client.getCellLive(op, true).catch(() => null);

const ckb = await cell({ txHash: S5, index: 0 });
console.log("FINAL CkbOwned cell (S5 out 0) LIVE:", !!ckb);
if (ckb) {
  console.log("  capacity:", (BigInt(ckb.cellOutput.capacity) / 100000000n).toString(), "CKB");
  console.log("  lock hash:", ckb.cellOutput.lock.hash?.() ?? "(script)");
  console.log("  tag:", ckb.outputData.slice(4, 6), "(02=CKB_OWNED)");
  console.log("  data:", ckb.outputData);
}
const reg = await cell({ txHash: S5, index: 1 });
console.log("\ncontinuing registry (S5 out 1) LIVE:", !!reg);
if (reg) console.log("  new SMT root:", reg.outputData, "(nullifier inserted)");

console.log("\nconsumed (expect all FALSE):");
console.log("  CardanoBound (S4 out):", await live({ txHash: "0x838e39f2cfa9a2fdf60adb4f4016e7b5c86a41175eb6e06079d6acc949752a88", index: 0 }));
console.log("  registry genesis singleton:", await live({ txHash: "0x4e159851cb5459f41fd9548748c48ad378453dad278b0b39a16aa513057714d7", index: 0 }));
console.log("  genesis CkbOwned cell:", await live({ txHash: "0x408d9c2862a437c751c5a93f2e7ff6316e66f495826d2939b5193952783bcfe8", index: 0 }));
process.exit(0);
