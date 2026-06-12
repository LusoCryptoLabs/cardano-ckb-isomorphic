// deploy_osmo.mjs — store + instantiate the ckb-verifier contract on Osmosis testnet (osmo-test-5) and run a
// LIVE VerifyCkbProof query of the real CKB-state Groth16 proof on a real Cosmos node (the reverse leg, live).
// Ready to run the moment the deployer address is funded; if the balance is 0 it prints the faucet and exits.
//   wsl: build the wasm first ->  cd contract && RUSTFLAGS="-C link-arg=--allow-undefined" cargo build --release --target wasm32-unknown-unknown --lib
//   node deploy_osmo.mjs
import { DirectSecp256k1HdWallet } from "@cosmjs/proto-signing";
import { SigningCosmWasmClient } from "@cosmjs/cosmwasm-stargate";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const RPC = process.env.OSMO_RPC || "https://rpc.testnet.osmosis.zone";
const DENOM = "uosmo";
const KEYFILE = path.join(os.homedir(), ".chiral", "osmo_testnet_deployer.key");
// the MVP-lowered wasm (bulk-memory/sign-ext lowered by wasm-opt for wasmd compatibility) if present, else raw.
const WASMDIR = path.resolve(HERE, "contract/target/wasm32-unknown-unknown/release");
const WASM = fs.existsSync(path.join(WASMDIR, "ckb_verifier.mvp.wasm")) ? path.join(WASMDIR, "ckb_verifier.mvp.wasm") : path.join(WASMDIR, "ckb_verifier.wasm");
const REDEEMER = path.resolve(HERE, "../ckb-to-cardano/circuit/ceremony/leap_bound_windowed_redeemer.json");

// public_inputs_dec -> 32-byte little-endian hex (the contract's raw-scalar form)
const decToLe32 = (dec) => { let n = BigInt(dec); const o = Buffer.alloc(32); for (let i = 0; i < 32; i++) { o[i] = Number(n & 0xffn); n >>= 8n; } return o.toString("hex"); };

async function main() {
  if (!fs.existsSync(KEYFILE)) { console.error("no key file; run gen_osmo_wallet.mjs first"); process.exit(1); }
  const wallet = await DirectSecp256k1HdWallet.fromMnemonic(fs.readFileSync(KEYFILE, "utf8").trim(), { prefix: "osmo" });
  const [acct] = await wallet.getAccounts();
  console.log("deployer:", acct.address, "| RPC:", RPC);

  const client = await SigningCosmWasmClient.connectWithSigner(RPC, wallet);
  // explicit fees (0.025 uosmo/gas) so we don't depend on a GasPrice instance matching cosmjs's internal copy.
  const fee = (gas) => ({ amount: [{ denom: DENOM, amount: String(Math.ceil(gas * 0.035)) }], gas: String(gas) });
  const bal = await client.getBalance(acct.address, DENOM);
  console.log("balance:", bal.amount, bal.denom);
  if (BigInt(bal.amount) === 0n) {
    console.log("\nADDRESS NOT FUNDED. Fund it at https://faucet.testnet.osmosis.zone/ then re-run.");
    console.log("address:", acct.address);
    return;
  }

  const wasm = new Uint8Array(fs.readFileSync(WASM));
  console.log("\nstoring wasm:", wasm.length, "bytes ...");
  const up = await client.upload(acct.address, wasm, fee(12000000));
  console.log("  codeId:", up.codeId, "| tx:", up.transactionHash);

  console.log("instantiating ...");
  const inst = await client.instantiate(acct.address, up.codeId, {}, "ckb-verifier", fee(1000000), { admin: acct.address });
  console.log("  contract:", inst.contractAddress, "| tx:", inst.transactionHash);

  // build the live verification message from the real redeemer
  const R = JSON.parse(fs.readFileSync(REDEEMER, "utf8"));
  const hx = (s) => s.replace(/^0x/, "");
  const fields = {
    a: hx(R.proof.a), b: hx(R.proof.b), c: hx(R.proof.c),
    alpha: hx(R.vk.alpha_g1), beta: hx(R.vk.beta_g2), gamma: hx(R.vk.gamma_g2), delta: hx(R.vk.delta_g2),
    ic: R.vk.ic.map(hx), public_inputs: R.public_inputs_dec.map(decToLe32),
  };
  const out = { codeId: up.codeId, contract: inst.contractAddress, store_tx: up.transactionHash, instantiate_tx: inst.transactionHash };

  // try the free smart query first; the in-wasm pairing may exceed the node's query gas cap, in which case run
  // it as a gas-paid AssertCkbProof tx (which succeeds iff the proof verifies).
  try {
    console.log("querying VerifyCkbProof (the real CKB-state proof) ...");
    const res = await client.queryContractSmart(inst.contractAddress, { verify_ckb_proof: fields });
    console.log("  query result:", JSON.stringify(res));
    out.query_valid = res.valid;
    console.log(res.valid ? "\nLIVE: a real Cosmos node verified the bridge's CKB-state proof (query)." : "\nunexpected: proof did not verify");
  } catch (e) {
    console.log("  query did not fit the gas cap:", (e.message || e).slice(0, 120));
    console.log("running AssertCkbProof as a tx (succeeds iff the proof verifies) ...");
    const exec = await client.execute(acct.address, inst.contractAddress, { assert_ckb_proof: fields }, fee(120000000));
    out.assert_tx = exec.transactionHash; out.assert_gas_used = exec.gasUsed;
    console.log("  tx:", exec.transactionHash, "| gas used:", exec.gasUsed);
    console.log("\nLIVE: the tx SUCCEEDED, so a real Cosmos node verified the bridge's CKB-state proof on-chain.");
  }

  fs.writeFileSync(path.join(HERE, "osmo_deploy.json"), JSON.stringify(out, null, 2));
  console.log("wrote osmo_deploy.json");
}
main().catch((e) => { console.error("ERR:", e?.message || e); process.exit(1); });
