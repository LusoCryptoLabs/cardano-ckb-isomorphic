// relayer.mjs - a PERMISSIONLESS relayer daemon (skeleton) for the Cardano⇄CKB bridge.
//
// ANYONE can run this - it holds no special authority. It watches CKB (Pudge) for relay-escrow deposits
// and, when the bridge event is proven (the AUTHENTICATED tx-set checkpoint exists on-chain), relays them:
// it submits the proof-gated completion tx and keeps the escrow as its fee. The validators are proof-gated
// (no admin keys), so a relayer can't forge - only fail to relay, and the depositor can self-relay/refund.
//
// This is the OFF-CHAIN plumbing (gap #5). Production extends it with: (1) watching BOTH chains, (2) building
// the Groth16 proof (CKB→Cardano) / fetching the Mithril cert + advancing the light-client checkpoint
// (Cardano→CKB), (3) handling Mithril certification latency, reorgs, retries, and (4) monitoring. The
// on-chain mechanics it drives (escrow relay + refund, authenticated checkpoint, burn-gated unlock) are all
// proven live - see docs/TESTNET_LOG.md.
//
// Usage:  RELAYER_KEY=/path/to/key node relayer.mjs [--once] [--interval=15000]
import { ccc } from "@ckb-ccc/core";
import fs from "node:fs";

// ---- config: the deployed on-chain artifacts this relayer drives (Pudge) ----
const CFG = {
  escrowCodeHash: "0x9e57e08347a643f9fb27d85f0ccd2d1c44c59ec133bc54be9b5b562c5d11202c",
  escrowCodeCell: { txHash: "0xf5208fbc4efef7665f5c6df9278c848936bb81e4871af5b361916185360ce805", index: 0 },
  // the authenticated tx-set checkpoint (TxSetCert-verified). Its presence as a cellDep proves the bridge event.
  authCheckpoint: { txHash: "0xe4e1b0c60509c784648debee6827f52043914c7f600bba9652bf1d558f619c2f", index: 0 },
  feeMinShannon: 2_000_000n, // network fee kept aside; the rest of the escrow is the relayer's reward
  // the Cardano side it watches: the live Mithril preview aggregator (CardanoTransactions certs)
  mithrilAggregator: "https://aggregator.testing-preview.api.mithril.network/aggregator",
  // the tx-set root currently anchored on-chain (the TxSetCert-authenticated checkpoint published this)
  onchainTxRoot: "ee048053e89cc50814df37b07cb58505dfd07dc066ed5dc3c3b61f5fefffd519",
};

// ---- Cardano watch: fetch the latest Mithril CardanoTransactions cert from the live aggregator ----
async function watchCardano() {
  try {
    const arts = await (await fetch(`${CFG.mithrilAggregator}/artifact/cardano-transactions`, { headers: { accept: "application/json" } })).json();
    if (!Array.isArray(arts) || !arts.length) { console.log("  [cardano] aggregator returned no snapshots"); return null; }
    const a = arts[0];
    const ch = a.certificate_hash || a.hash;
    let signed = false;
    if (ch) {
      const cert = await (await fetch(`${CFG.mithrilAggregator}/certificate/${ch}`, { headers: { accept: "application/json" } })).json();
      signed = !!(cert && cert.multi_signature);
    }
    console.log(`  [cardano] latest Mithril cert: root ${String(a.merkle_root).slice(0, 16)}.. epoch ${a.epoch ?? a.beacon?.epoch} block ${a.block_number} signed=${signed}`);
    console.log(`            (the on-chain authenticated checkpoint anchors ${CFG.onchainTxRoot.slice(0, 16)}..; production advances the light-client checkpoint to each new cert via AdvanceCert/TxSetCert)`);
    return a;
  } catch (e) { console.log("  [cardano] aggregator fetch failed:", (e.message || String(e)).slice(0, 80)); return null; }
}
const once = process.argv.includes("--once");
const intervalArg = process.argv.find(a => a.startsWith("--interval="));
const intervalMs = intervalArg ? Number(intervalArg.split("=")[1]) : 15000;

const client = new ccc.ClientPublicTestnet();
const relayer = new ccc.SignerCkbPrivateKey(client, fs.readFileSync(process.env.RELAYER_KEY || "/root/.pudge_key", "utf8").trim());
const relayerLock = (await relayer.getAddressObjs())[0].script;
const escrowLock = ccc.Script.from({ codeHash: CFG.escrowCodeHash, hashType: "data1", args: "0x" });

// Is the bridge event proven? (the authenticated checkpoint cell is live)
async function bridgeEventProven() {
  const c = await client.getCell(CFG.authCheckpoint);
  return !!c;
}

async function relayOne(cell) {
  const cap = BigInt(cell.cellOutput.capacity);
  const tx = ccc.Transaction.from({
    inputs: [{ previousOutput: cell.outPoint }],
    outputs: [{ lock: relayerLock, capacity: cap - CFG.feeMinShannon }], outputsData: ["0x"],
    cellDeps: [{ outPoint: CFG.escrowCodeCell, depType: "code" }, { outPoint: CFG.authCheckpoint, depType: "code" }],
  });
  const h = await client.sendTransaction(await relayer.signTransaction(tx));
  console.log(`  RELAYED ${cell.outPoint.txHash.slice(0, 14)}..:${Number(cell.outPoint.index)}  reward≈${Number(cap) / 1e8} CKB  tx ${h}`);
  await client.waitTransaction(h, 1, { timeout: 120000 });
  return h;
}

async function scan() {
  if (!(await bridgeEventProven())) { console.log("  bridge event not yet proven (no authenticated checkpoint) - waiting"); return 0; }
  let n = 0;
  for await (const cell of client.findCellsByLock(escrowLock, null, true)) {
    try { await relayOne(cell); n++; }
    catch (e) { console.log(`  skip ${cell.outPoint.txHash.slice(0, 14)}..: ${(e.message || String(e)).split("\n")[0].slice(0, 80)}`); }
  }
  return n;
}

console.log(`permissionless relayer up. lock ${relayerLock.hash().slice(0, 18)}..  escrow ${CFG.escrowCodeHash.slice(0, 18)}..  mode ${once ? "once" : "loop@" + intervalMs + "ms"}`);
do {
  console.log(`[${new Date().toISOString()}] --- watch+relay pass ---`);
  await watchCardano();            // watch the Cardano side (live Mithril cert)
  const n = await scan();          // relay on the CKB side
  console.log(`[${new Date().toISOString()}] pass complete - relayed ${n} deposit(s)`);
  if (!once) await new Promise(r => setTimeout(r, intervalMs));
} while (!once);
process.exit(0);
