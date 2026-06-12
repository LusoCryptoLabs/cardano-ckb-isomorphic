// deploy_chickb.mjs — Fix #2 live: deploy the updated ckb-verifier on osmo-test-5, create the χCKB token-factory
// denom, and MINT χCKB gated on the real CKB-state proof. Result: a wallet/explorer-visible wrapped-CKB native
// bank denom on Cosmos (factory/<contract>/uchickb), the forward mirror of χOSMO-on-CKB.
import { DirectSecp256k1HdWallet } from "@cosmjs/proto-signing";
import { SigningCosmWasmClient } from "@cosmjs/cosmwasm-stargate";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const RPC = process.env.OSMO_RPC || "https://rpc.testnet.osmosis.zone";
const DENOM = "uosmo";
const SUBDENOM = "uchickb";
const KEYFILE = path.join(os.homedir(), ".chiral", "osmo_testnet_deployer.key");
const WASM = path.resolve(HERE, "contract/target/wasm32-unknown-unknown/release/ckb_verifier.mvp.wasm");
const REDEEMER = path.resolve(HERE, "../ckb-to-cardano/circuit/ceremony/leap_bound_windowed_redeemer.json");
const decToLe32 = (dec) => { let n = BigInt(dec); const o = Buffer.alloc(32); for (let i = 0; i < 32; i++) { o[i] = Number(n & 0xffn); n >>= 8n; } return o.toString("hex"); };

async function main() {
  const wallet = await DirectSecp256k1HdWallet.fromMnemonic(fs.readFileSync(KEYFILE, "utf8").trim(), { prefix: "osmo" });
  const [acct] = await wallet.getAccounts();
  const client = await SigningCosmWasmClient.connectWithSigner(RPC, wallet);
  const fee = (gas) => ({ amount: [{ denom: DENOM, amount: String(Math.ceil(gas * 0.035)) }], gas: String(gas) });
  console.log("deployer:", acct.address, "| balance:", (await client.getBalance(acct.address, DENOM)).amount, DENOM);

  const wasm = new Uint8Array(fs.readFileSync(WASM));
  console.log("storing wasm:", wasm.length, "bytes ...");
  const up = await client.upload(acct.address, wasm, fee(20000000));
  console.log("  codeId:", up.codeId);
  const inst = await client.instantiate(acct.address, up.codeId, {}, "chickb-minter", fee(1000000), { admin: acct.address });
  const contract = inst.contractAddress;
  console.log("  contract:", contract);

  // create the token-factory denom (fund the contract for the creation fee).
  const denom = `factory/${contract}/${SUBDENOM}`;
  console.log("creating denom", denom, "...");
  await client.execute(acct.address, contract, { create_chi_ckb_denom: { subdenom: SUBDENOM } }, fee(2000000), "", [{ denom: DENOM, amount: "20000000" }]);
  console.log("  denom created");

  // mint χCKB gated on the real CKB-state proof (raw mechanism demo).
  const R = JSON.parse(fs.readFileSync(REDEEMER, "utf8"));
  const hx = (s) => s.replace(/^0x/, "");
  const msg = { mint_chi_ckb_raw: {
    public_inputs: R.public_inputs_dec.map(decToLe32),
    proof: { a: hx(R.proof.a), b: hx(R.proof.b), c: hx(R.proof.c) },
    vk: { alpha: hx(R.vk.alpha_g1), beta: hx(R.vk.beta_g2), gamma: hx(R.vk.gamma_g2), delta: hx(R.vk.delta_g2), ic: R.vk.ic.map(hx) },
    subdenom: SUBDENOM, to: acct.address, amount: "1000000",
  } };
  console.log("minting χCKB gated on the real CKB proof ...");
  const mint = await client.execute(acct.address, contract, msg, fee(80000000));
  console.log("  mint tx:", mint.transactionHash);

  const bal = await client.getBalance(acct.address, denom);
  console.log("\nχCKB balance:", bal.amount, bal.denom);
  console.log(bal.amount !== "0" ? "LIVE: wrapped CKB (χCKB) minted on Cosmos, gated on the CKB-state proof, as a native bank denom." : "mint did not credit (check)");
  fs.writeFileSync(path.join(HERE, "chickb_deploy.json"), JSON.stringify({ codeId: up.codeId, contract, denom, mint_tx: mint.transactionHash, amount: bal.amount }, null, 2));
  console.log("wrote chickb_deploy.json");
}
main().catch((e) => { console.error("ERR:", (e.message || e)); process.exit(1); });
