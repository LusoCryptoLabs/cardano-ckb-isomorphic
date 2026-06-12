// mint_chickb_only.mjs — execute MintChiCkbRaw on the EXISTING chickb contract (denom already created), gated on
// the real CKB proof, with a high gas budget (the in-wasm BLS pairing is heavy). Probes whether the in-wasm
// pairing mint fits in an Osmosis block (max_gas 300M).
import { DirectSecp256k1HdWallet } from "@cosmjs/proto-signing";
import { SigningCosmWasmClient } from "@cosmjs/cosmwasm-stargate";
import fs from "node:fs"; import os from "node:os"; import path from "node:path"; import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const RPC = "https://rpc.testnet.osmosis.zone";
const CONTRACT = process.env.CONTRACT || "osmo1yewevzdvy8nynuzszhjxwxr2caze93cc6w3s3g2n3zc0gt9fmn6sya9x04";
const SUBDENOM = "uchickb";
const GAS = Number(process.env.GAS || 250000000);
const KEYFILE = path.join(os.homedir(), ".chiral", "osmo_testnet_deployer.key");
const REDEEMER = path.resolve(HERE, "../ckb-to-cardano/circuit/ceremony/leap_bound_windowed_redeemer.json");
const decToLe32 = (dec) => { let n = BigInt(dec); const o = Buffer.alloc(32); for (let i = 0; i < 32; i++) { o[i] = Number(n & 0xffn); n >>= 8n; } return o.toString("hex"); };

const wallet = await DirectSecp256k1HdWallet.fromMnemonic(fs.readFileSync(KEYFILE, "utf8").trim(), { prefix: "osmo" });
const [acct] = await wallet.getAccounts();
const client = await SigningCosmWasmClient.connectWithSigner(RPC, wallet);
const fee = { amount: [{ denom: "uosmo", amount: String(Math.ceil(GAS * 0.035)) }], gas: String(GAS) };
const R = JSON.parse(fs.readFileSync(REDEEMER, "utf8"));
const hx = (s) => s.replace(/^0x/, "");
const msg = { mint_chi_ckb_raw: {
  public_inputs: R.public_inputs_dec.map(decToLe32),
  proof: { a: hx(R.proof.a), b: hx(R.proof.b), c: hx(R.proof.c) },
  vk: { alpha: hx(R.vk.alpha_g1), beta: hx(R.vk.beta_g2), gamma: hx(R.vk.gamma_g2), delta: hx(R.vk.delta_g2), ic: R.vk.ic.map(hx) },
  subdenom: SUBDENOM, to: acct.address, amount: "1000000",
} };
console.log("minting χCKB on", CONTRACT.slice(0, 16), "with gas", GAS, "...");
try {
  const res = await client.execute(acct.address, CONTRACT, msg, fee);
  console.log("MINT tx:", res.transactionHash, "| gasUsed", res.gasUsed, "/", res.gasWanted);
  const denom = `factory/${CONTRACT}/${SUBDENOM}`;
  console.log("χCKB balance:", (await client.getBalance(acct.address, denom)).amount, denom);
  fs.writeFileSync(path.join(HERE, "chickb_mint.json"), JSON.stringify({ contract: CONTRACT, denom, mint_tx: res.transactionHash, gas_used: res.gasUsed }, null, 2));
} catch (e) { console.log("mint failed:", (e.message || e).slice(0, 300)); }
