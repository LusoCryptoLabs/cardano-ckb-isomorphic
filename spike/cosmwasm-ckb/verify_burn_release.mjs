// verify_burn_release.mjs — RETURN leg, on-chain verification. Proves that the live χOSMO-burn Groth16 proof
// (leap_burn_windowed, bound to the real CKB burn 0x4ca0e3c0…) is (1) bound to the NAMED burn event exactly as
// the Cosmos contract's derive_burn_inputs would, and (2) VERIFIED by the live osmo-test-5 ckb-verifier
// contract. This is the on-chain half of ReleaseOnCkbBurn; the only step left for a full uosmo payout is the
// BankMsg::Send execute, which runs the same pairing and is host-fn-gated (Neutron), exactly like the χCKB mint.
import { SigningCosmWasmClient } from "@cosmjs/cosmwasm-stargate";
import { DirectSecp256k1HdWallet } from "@cosmjs/proto-signing";
import { bls12_381 as bls } from "@noble/curves/bls12-381.js";
import { blake2b } from "@noble/hashes/blake2.js";
import fs from "node:fs"; import os from "node:os"; import path from "node:path"; import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const RPC = process.env.OSMO_RPC || "https://rpc.testnet.osmosis.zone";
const CONTRACT = process.env.CONTRACT || JSON.parse(fs.readFileSync(path.join(HERE, "osmo_deploy.json"), "utf8")).contract;
const ONCHAIN = path.resolve(HERE, "../../relayer/onchain");
const R = JSON.parse(fs.readFileSync(path.join(ONCHAIN, "leap_burn_windowed_redeemer.json"), "utf8"));
const EV = JSON.parse(fs.readFileSync(path.join(ONCHAIN, "leap_burn_windowed_event.json"), "utf8"));
const KEYFILE = path.join(os.homedir(), ".chiral", "osmo_testnet_deployer.key");

const ORD = bls.fields.Fr.ORDER;
const hx = (s) => Buffer.from(s.replace(/^0x/, ""), "hex");
const leBig = (b) => { let n = 0n; for (let i = b.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(b[i]); return n; };
const bigLe32 = (n) => { const o = Buffer.alloc(32); for (let i = 0; i < 32; i++) { o[i] = Number(n & 0xffn); n >>= 8n; } return o; };
const leMod = (b) => bigLe32(leBig(b) % ORD).toString("hex");
const u64le = (n) => bigLe32(BigInt(n) % ORD).toString("hex");
const decToLe32 = (dec) => bigLe32(BigInt(dec) % ORD).toString("hex");

// 1) derive the 5 public inputs from the NAMED burn event, exactly as the contract's derive_burn_inputs does.
const amount16 = Buffer.alloc(16); { let n = BigInt(EV.amount); for (let i = 0; i < 16; i++) { amount16[i] = Number(n & 0xffn); n >>= 8n; } }
const seal = hx(EV.seal);
const commit = Buffer.from(blake2b(Buffer.concat([amount16, hx(EV.recipient), seal]), { dkLen: 32 })); // amount||recip20||seal
const derived = [leMod(hx(EV.window_root)), leMod(seal), leMod(commit), u64le(EV.tip_height), u64le(EV.k)];
const fromProof = R.public_inputs_dec.map(decToLe32);

console.log("RETURN-leg burn event:", JSON.stringify(EV));
console.log("\nbinding check — derive_burn_inputs(event) vs the proof's public inputs:");
let bound = true;
const names = ["window_root", "seal", "commitment", "tip_height", "k"];
for (let i = 0; i < 5; i++) {
  const ok = derived[i] === fromProof[i];
  bound &&= ok;
  console.log(`  ${names[i].padEnd(11)} ${ok ? "MATCH" : "DIFFER"}  ${derived[i]}`);
}
if (!bound) { console.error("\nFATAL: the proof's public inputs are NOT the contract's derived burn inputs."); process.exit(1); }
console.log("BOUND: the proof attests THIS named CKB burn (amount+recipient+seal committed in-circuit).");

// 2) verify the proof on the LIVE osmo-test-5 contract.
const h = (s) => s.replace(/^0x/, "");
const fields = {
  a: h(R.proof.a), b: h(R.proof.b), c: h(R.proof.c),
  alpha: h(R.vk.alpha_g1), beta: h(R.vk.beta_g2), gamma: h(R.vk.gamma_g2), delta: h(R.vk.delta_g2),
  ic: R.vk.ic.map(h), public_inputs: fromProof,
};
const wallet = await DirectSecp256k1HdWallet.fromMnemonic(fs.readFileSync(KEYFILE, "utf8").trim(), { prefix: "osmo" });
const [acct] = await wallet.getAccounts();
const client = await SigningCosmWasmClient.connectWithSigner(RPC, wallet);
const out = { contract: CONTRACT, burn_tx: EV.seal, amount: EV.amount, recipient: EV.recipient, recipientAddr: JSON.parse(fs.readFileSync(path.join(ONCHAIN, "xosmo_burn_live.json"), "utf8")).recipientAddr };

console.log("\nquerying VerifyCkbProof on the live osmo-test-5 contract", CONTRACT.slice(0, 16), "…");
try {
  const res = await client.queryContractSmart(CONTRACT, { verify_ckb_proof: fields });
  out.query_valid = res.valid;
  console.log("  query result:", JSON.stringify(res));
  console.log(res.valid
    ? "\nLIVE: a real Osmosis node verified the χOSMO-BURN proof on-chain, bound to the named CKB burn."
    : "\nunexpected: the burn proof did not verify");
} catch (e) {
  console.log("  query did not fit the gas cap:", (e.message || e).slice(0, 140));
  const fee = (gas) => ({ amount: [{ denom: "uosmo", amount: String(Math.ceil(gas * 0.035)) }], gas: String(gas) });
  const exec = await client.execute(acct.address, CONTRACT, { assert_ckb_proof: fields }, fee(120000000));
  out.assert_tx = exec.transactionHash; out.assert_gas_used = exec.gasUsed;
  console.log("  AssertCkbProof tx:", exec.transactionHash, "| gas used:", exec.gasUsed);
  console.log("\nLIVE: the AssertCkbProof tx SUCCEEDED, so a real Osmosis node verified the χOSMO-burn proof on-chain.");
}
fs.writeFileSync(path.join(HERE, "burn_release_verified.json"), JSON.stringify(out, null, 2));
console.log("wrote burn_release_verified.json");
