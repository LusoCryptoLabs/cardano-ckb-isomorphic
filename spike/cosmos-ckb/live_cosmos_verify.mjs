// live_cosmos_verify.mjs — run the Cosmos finality+inclusion verifier on the LIVE CKB-VM (Pudge), not just
// ckb-debugger. Deploys tendermint_inclusion, locks a cell under the real cosmoshub-4 validator-set anchor
// (lock args = validators_hash), then UNLOCKS it by supplying a Cosmos tx-inclusion proof in the witness. A
// successful spend means CKB-VM verified, on-chain, that a real Cosmos tx is in a finalized block.
import { ccc } from "@ckb-ccc/core";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const RPC = process.env.COSMOS_RPC || "https://cosmos-rpc.publicnode.com";
const BIN = path.resolve(HERE, "../burn-gated-unlock/target/riscv64imac-unknown-none-elf/release/tendermint_inclusion");
const DEPLOY = path.join(HERE, "tm_deploy.json");
const get = async (p) => (await fetch(RPC + p, { signal: AbortSignal.timeout(20000) })).json();
const sh = JSON.parse(fs.readFileSync(path.join(HERE, "commit.json"), "utf8"));
const vals = JSON.parse(fs.readFileSync(path.join(HERE, "validators.json"), "utf8"));
const H = sh.header, c = sh.commit;
const SHA = (b) => crypto.createHash("sha256").update(b).digest();
const u16 = (n) => { const b = Buffer.alloc(2); b.writeUInt16LE(n); return b; };
const u32 = (n) => { const b = Buffer.alloc(4); b.writeUInt32LE(n); return b; };
const u64 = (n) => { const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(n)); return b; };
const i64 = (n) => { const b = Buffer.alloc(8); b.writeBigInt64LE(BigInt(n)); return b; };
const hx = (s) => Buffer.from(s, "hex");
const b64 = (s) => Buffer.from(s, "base64");
const ts = (iso) => { const m = iso.match(/^(.*?)(?:\.(\d+))?Z$/); return { seconds: Math.floor(Date.parse(m[1] + "Z") / 1000), nanos: m[2] ? parseInt(m[2].padEnd(9, "0").slice(0, 9), 10) : 0 }; };
function varint(n) { const o = []; let v = BigInt(n); while (v > 0x7fn) { o.push(Number((v & 0x7fn) | 0x80n)); v >>= 7n; } o.push(Number(v)); return Buffer.from(o); }
const tag = (f, w) => varint((f << 3) | w);
const pbBytes = (f, b) => Buffer.concat([tag(f, 2), varint(b.length), b]);
const pbVar = (f, n) => Buffer.concat([tag(f, 0), varint(n)]);
const cdcStr = (s) => (s ? pbBytes(1, Buffer.from(s, "utf8")) : Buffer.alloc(0));
const cdcInt = (n) => pbVar(1, n);
const cdcBytes = (h) => { const b = h ? hx(h) : Buffer.alloc(0); return b.length ? pbBytes(1, b) : Buffer.alloc(0); };
const versionEnc = (bl, ap) => { const o = []; if (bl) o.push(pbVar(1, bl)); if (ap) o.push(pbVar(2, ap)); return Buffer.concat(o); };
const timeEnc = (iso) => { const t = ts(iso); const o = []; if (t.seconds) o.push(pbVar(1, t.seconds)); if (t.nanos) o.push(pbVar(2, t.nanos)); return Buffer.concat(o); };
const partSetEnc = (t, h) => { const o = []; if (t) o.push(pbVar(1, t)); o.push(pbBytes(2, hx(h))); return Buffer.concat(o); };
const blockIDEnc = (b) => Buffer.concat([pbBytes(1, hx(b.hash)), pbBytes(2, partSetEnc(b.parts.total, b.parts.hash))]);
const leafHash = (b) => SHA(Buffer.concat([Buffer.from([0]), b]));
const innerHash = (l, r) => SHA(Buffer.concat([Buffer.from([1]), l, r]));
const splitPoint = (n) => { let k = 1; while (k * 2 < n) k *= 2; return k; };
const merkleRoot = (it) => it.length === 1 ? leafHash(it[0]) : innerHash(merkleRoot(it.slice(0, splitPoint(it.length))), merkleRoot(it.slice(splitPoint(it.length))));
function buildAunts(it, i) { const t = []; (function r(it, i) { if (it.length <= 1) return; const k = splitPoint(it.length); if (i < k) { t.push(merkleRoot(it.slice(k))); r(it.slice(0, k), i); } else { t.push(merkleRoot(it.slice(0, k))); r(it.slice(k), i - k); } })(it, i); return t.reverse(); }

async function buildBlob() {
  const blk = await get(`/block?height=${H.height}`);
  const txs = (blk.result.block.data.txs || []).map((t) => b64(t));
  const items = txs.map((t) => SHA(t)), index = 0, aunts = buildAunts(items, index);
  const leaves = [versionEnc(Number(H.version.block || 0), Number(H.version.app || 0)), cdcStr(H.chain_id), cdcInt(H.height), timeEnc(H.time),
    blockIDEnc(H.last_block_id), cdcBytes(H.last_commit_hash), cdcBytes(H.data_hash), cdcBytes(H.validators_hash), cdcBytes(H.next_validators_hash),
    cdcBytes(H.consensus_hash), cdcBytes(H.app_hash), cdcBytes(H.last_results_hash), cdcBytes(H.evidence_hash), cdcBytes(H.proposer_address)];
  const p = [Buffer.from([leaves.length])];
  for (const l of leaves) p.push(u16(l.length), l);
  const cid = Buffer.from(H.chain_id, "utf8");
  p.push(Buffer.from([cid.length]), cid, u64(H.height), u64(c.round), u32(c.block_id.parts.total), hx(c.block_id.parts.hash), u16(vals.length));
  for (const v of vals) p.push(b64(v.pub_key.value), u64(v.voting_power));
  const addrIdx = new Map(vals.map((v, i) => [v.address, i]));
  const pre = c.signatures.filter((s) => s.block_id_flag === 2 && s.signature);
  p.push(u16(pre.length));
  for (const s of pre) { const t = ts(s.timestamp); p.push(u16(addrIdx.get(s.validator_address)), i64(t.seconds), u32(t.nanos), b64(s.signature)); }
  p.push(u16(txs[index].length), txs[index], u32(index), u32(txs.length), Buffer.from([aunts.length]));
  for (const a of aunts) p.push(a);
  return Buffer.concat(p);
}

async function main() {
  const client = new ccc.ClientPublicTestnet();
  const signer = new ccc.SignerCkbPrivateKey(client, fs.readFileSync(path.join(os.homedir(), ".chiral", "pudge_relayer.key"), "utf8").trim());
  const myLock = (await signer.getAddressObjs())[0].script;
  const wait = (h) => client.waitTransaction(h, 1, { timeout: 180000 });

  // deploy (cache)
  let dep;
  if (fs.existsSync(DEPLOY)) dep = JSON.parse(fs.readFileSync(DEPLOY, "utf8"));
  if (!dep || !(await client.getCellLive({ txHash: dep.txHash, index: 0 }, true).catch(() => null))) {
    const data = ccc.hexFrom(new Uint8Array(fs.readFileSync(BIN)));
    const codeHash = ccc.hashCkb(data);
    const tx = ccc.Transaction.from({ outputs: [{ lock: myLock }], outputsData: [data] });
    await tx.completeInputsByCapacity(signer); await tx.completeFeeBy(signer, 1000);
    const h = await client.sendTransaction(await signer.signTransaction(tx)); await wait(h);
    dep = { txHash: h, index: 0, codeHash, dep: { outPoint: { txHash: h, index: 0 }, depType: "code" } };
    fs.writeFileSync(DEPLOY, JSON.stringify(dep, null, 2));
    console.log("DEPLOYED tendermint_inclusion:", h, "codeHash", codeHash);
  } else console.log("verifier already deployed:", dep.codeHash);

  // lock a cell under the real cosmoshub-4 validator-set anchor
  const anchor = "0x" + H.validators_hash.toLowerCase();
  const verifierLock = ccc.Script.from({ codeHash: dep.codeHash, hashType: "data1", args: anchor });
  const lockTx = ccc.Transaction.from({ outputs: [{ lock: verifierLock, capacity: 300_00000000n }], outputsData: ["0x"] });
  await lockTx.completeInputsByCapacity(signer); await lockTx.completeFeeBy(signer, 1000);
  const h1 = await client.sendTransaction(await signer.signTransaction(lockTx)); await wait(h1);
  console.log("LOCKED a cell under the Cosmos anchor:", h1 + ":0", "| anchor", anchor.slice(0, 14));

  // unlock it with the Cosmos proof (no signature; the verifier IS the lock)
  const blob = await buildBlob();
  const FEE = 1_000_000n;
  const unlockTx = ccc.Transaction.from({
    inputs: [{ previousOutput: { txHash: h1, index: 0 }, since: 0n }],
    outputs: [{ lock: myLock, capacity: 300_00000000n - FEE }], outputsData: ["0x"], cellDeps: [dep.dep],
  });
  unlockTx.setWitnessArgsAt(0, ccc.WitnessArgs.from({ lock: "0x" + blob.toString("hex") }));
  const h2 = await client.sendTransaction(unlockTx); await wait(h2);
  console.log("\n=== UNLOCKED on live CKB-VM by a Cosmos tx-inclusion proof ===");
  console.log("proof blob:", blob.length, "bytes | unlock tx:", h2);
  console.log("explorer: https://testnet.explorer.nervos.org/transaction/" + h2);
  process.exit(0);
}
main().catch((e) => { console.error("ERR:", e?.message || e); process.exit(1); });
