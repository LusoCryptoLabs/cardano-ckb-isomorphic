// Run ONLY the authenticated advance: spend the epoch-320 checkpoint -> epoch-321 cell. The verifier
// type script runs the FULL Mithril cert verify in-VM (BLS aggregate + 2330-index lottery + Merkle + quorum).
import { ccc } from "@ckb-ccc/core";
import fs from "node:fs";
const ADV = fs.readFileSync("/tmp/lcadvance/advance_state.hex", "utf8").trim();
const DEPLOY = { txHash: "0xb34aa21aa5ac00836cfef39f7113c2117f898e8bb82e9e88e9ed06b419e8da1d", index: 0 };
const GENESIS = { txHash: "0x122b71f0b6b6107a30c8c2efe0b8bfbaefa6a425c0dd57e7f0d1c1356953ada1", index: 0 };

const client = new ccc.ClientPublicTestnet();
const signer = new ccc.SignerCkbPrivateKey(client, fs.readFileSync("/root/.pudge_key", "utf8").trim());
const myLock = (await signer.getAddressObjs())[0].script;
const code = ccc.hexFrom(new Uint8Array(fs.readFileSync("/tmp/lcadvance/lca.bin")));
const verifier = ccc.Script.from({ codeHash: ccc.hashCkb(code), hashType: "data1", args: "0x" });
const codeDep = { outPoint: DEPLOY, depType: "code" };

const genCell = await client.getCell(GENESIS);
const cap = BigInt(genCell.cellOutput.capacity);
const t = ccc.Transaction.from({
  inputs: [{ previousOutput: GENESIS }],
  outputs: [{ lock: myLock, type: verifier, capacity: cap - 5_000_000n }], outputsData: [ADV],
  cellDeps: [codeDep],
});
await t.completeFeeBy(signer, 2000);
const h = await client.sendTransaction(await signer.signTransaction(t));
console.log("ADVANCE_TX", h);
process.exit(0);
