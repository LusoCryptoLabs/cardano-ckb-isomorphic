// deploy_osmo.mjs — store + instantiate the ckb-verifier contract on Osmosis testnet (osmo-test-5) and run a
// LIVE VerifyCkbProof query of the real CKB-state Groth16 proof on a real Cosmos node (the reverse leg, live).
// Ready to run the moment the deployer address is funded; if the balance is 0 it prints the faucet and exits.
//   wsl: build the wasm first ->  cd contract && RUSTFLAGS="-C link-arg=--allow-undefined" cargo build --release --target wasm32-unknown-unknown --lib
//   node deploy_osmo.mjs
import { DirectSecp256k1HdWallet } from "@cosmjs/proto-signing";
import { SigningCosmWasmClient } from "@cosmjs/cosmwasm-stargate";
import { GasPrice as GP } from "@cosmjs/stargate";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const RPC = process.env.OSMO_RPC || "https://rpc.testnet.osmosis.zone";
const DENOM = "uosmo";
const KEYFILE = path.join(os.homedir(), ".chiral", "osmo_testnet_deployer.key");
const WASM = path.resolve(HERE, "contract/target/wasm32-unknown-unknown/release/ckb_verifier.wasm");
const REDEEMER = path.resolve(HERE, "../ckb-to-cardano/circuit/ceremony/leap_bound_windowed_redeemer.json");

// public_inputs_dec -> 32-byte little-endian hex (the contract's raw-scalar form)
const decToLe32 = (dec) => { let n = BigInt(dec); const o = Buffer.alloc(32); for (let i = 0; i < 32; i++) { o[i] = Number(n & 0xffn); n >>= 8n; } return o.toString("hex"); };

async function main() {
  if (!fs.existsSync(KEYFILE)) { console.error("no key file; run gen_osmo_wallet.mjs first"); process.exit(1); }
  const wallet = await DirectSecp256k1HdWallet.fromMnemonic(fs.readFileSync(KEYFILE, "utf8").trim(), { prefix: "osmo" });
  const [acct] = await wallet.getAccounts();
  console.log("deployer:", acct.address, "| RPC:", RPC);

  const client = await SigningCosmWasmClient.connectWithSigner(RPC, wallet, { gasPrice: GP.fromString("0.025" + DENOM) });
  const bal = await client.getBalance(acct.address, DENOM);
  console.log("balance:", bal.amount, bal.denom);
  if (BigInt(bal.amount) === 0n) {
    console.log("\nADDRESS NOT FUNDED. Fund it at https://faucet.testnet.osmosis.zone/ then re-run.");
    console.log("address:", acct.address);
    return;
  }

  const wasm = new Uint8Array(fs.readFileSync(WASM));
  console.log("\nstoring wasm:", wasm.length, "bytes ...");
  const up = await client.upload(acct.address, wasm, "auto");
  console.log("  codeId:", up.codeId, "| tx:", up.transactionHash);

  console.log("instantiating ...");
  const inst = await client.instantiate(acct.address, up.codeId, {}, "ckb-verifier", "auto", { admin: acct.address });
  console.log("  contract:", inst.contractAddress, "| tx:", inst.transactionHash);

  // build the live VerifyCkbProof query from the real redeemer
  const R = JSON.parse(fs.readFileSync(REDEEMER, "utf8"));
  const hx = (s) => s.replace(/^0x/, "");
  const msg = { verify_ckb_proof: {
    a: hx(R.proof.a), b: hx(R.proof.b), c: hx(R.proof.c),
    alpha: hx(R.vk.alpha_g1), beta: hx(R.vk.beta_g2), gamma: hx(R.vk.gamma_g2), delta: hx(R.vk.delta_g2),
    ic: R.vk.ic.map(hx), public_inputs: R.public_inputs_dec.map(decToLe32),
  } };
  console.log("querying VerifyCkbProof (the real CKB-state proof) ...");
  const res = await client.queryContractSmart(inst.contractAddress, msg);
  console.log("  result:", JSON.stringify(res));
  console.log(res.valid ? "\nLIVE: a real Cosmos node verified the bridge's CKB-state proof." : "\nunexpected: proof did not verify on-chain");

  fs.writeFileSync(path.join(HERE, "osmo_deploy.json"), JSON.stringify({ codeId: up.codeId, contract: inst.contractAddress, store_tx: up.transactionHash, instantiate_tx: inst.transactionHash, valid: res.valid }, null, 2));
  console.log("wrote osmo_deploy.json");
}
main().catch((e) => { console.error("ERR:", e?.message || e); process.exit(1); });
