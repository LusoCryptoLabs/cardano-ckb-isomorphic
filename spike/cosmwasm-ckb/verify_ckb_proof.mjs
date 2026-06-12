// verify_ckb_proof.mjs — verify the bridge's CKB-state Groth16 proof (BLS12-381) off-chain, the exact proof
// Cardano already verifies. This pins the verification equation before porting it to a CosmWasm contract
// (CosmWasm 2.x has bls12_381 host functions, so a Cosmos chain can verify the SAME proof). Reverse direction
// of the Cosmos <-> CKB binding: Cosmos verifies CKB.
import { bls12_381 as bls } from "@noble/curves/bls12-381.js";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const R = JSON.parse(fs.readFileSync(path.resolve(HERE, "../ckb-to-cardano/circuit/ceremony/leap_bound_windowed_redeemer.json"), "utf8"));
const G1 = bls.G1.Point, G2 = bls.G2.Point, Fp12 = bls.fields.Fp12;
const hx = (s) => s.replace(/^0x/, "");

const a = G1.fromHex(hx(R.proof.a));
const b = G2.fromHex(hx(R.proof.b));
const c = G1.fromHex(hx(R.proof.c));
const alpha = G1.fromHex(hx(R.vk.alpha_g1));
const beta = G2.fromHex(hx(R.vk.beta_g2));
const gamma = G2.fromHex(hx(R.vk.gamma_g2));
const delta = G2.fromHex(hx(R.vk.delta_g2));
const ic = R.vk.ic.map((h) => G1.fromHex(hx(h)));
const pubs = R.public_inputs_dec.map((s) => BigInt(s));
console.log("public inputs:", pubs.length, "| ic points:", ic.length, "| (ic = pubs + 1):", ic.length === pubs.length + 1);

// vk_x = ic[0] + sum(pub_i * ic[i+1])
let vkx = ic[0];
for (let i = 0; i < pubs.length; i++) { if (pubs[i] !== 0n) vkx = vkx.add(ic[i + 1].multiply(pubs[i])); }

// Groth16: e(A, B) == e(alpha, beta) * e(vk_x, gamma) * e(C, delta)   (in GT)
const lhs = bls.pairing(a, b);
const rhs = Fp12.mul(Fp12.mul(bls.pairing(alpha, beta), bls.pairing(vkx, gamma)), bls.pairing(c, delta));
const ok = Fp12.eql(lhs, rhs);
console.log("\nGroth16 e(A,B) == e(alpha,beta)*e(vk_x,gamma)*e(C,delta):", ok);
console.log(ok ? "=> CKB-state proof VERIFIES off-chain. CosmWasm can verify the same proof via bls12_381 host fns." : "=> does not verify (check the equation/sign convention)");
