// xada_burn_orchestrate.mjs <burnTxid> - drive the χADA → ADA RETURN end to end from a confirmed CKB burn:
//   capture the burn body+offsets  ->  re-anchor the CKB-header checkpoint to cover the burn block
//   ->  prove the burn (REUSING the burn proving key, fast - not a fresh ceremony)  ->  lock the return escrow
//   ->  spend it via ada_escrow.Release (verifies the Groth16 proof on-chain)  ->  pay the ADA to the recipient.
// The amount + Cardano recipient are READ FROM THE BURN RECEIPT (the proof binds them), not supplied - so the
// relayer cannot redirect. Prints one JSON result line. Mirrors release_orchestrate.mjs (the χCKB reverse leg).
//
// NOTE (honest): each return re-anchors the checkpoint (several Cardano txs) because the on-chain CKB light
// client advances one block at a time. A production always-on self-serve return wants a checkpoint-advance
// daemon keeping ONE checkpoint current - then this skips the re-anchor + reuses a stable escrow.
import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { REPO_SH, shInvoke } from "./_rt.mjs";   // WSL (this box) vs native-Linux (VPS)

const HERE = path.dirname(fileURLToPath(import.meta.url));
const G16 = `${REPO_SH}/spike/ckb-to-cardano/groth16`;
const RELAYER = `${REPO_SH}/spike/ckb-to-cardano/relayer`;
const CER = `${REPO_SH}/spike/ckb-to-cardano/circuit/ceremony_xada_burn`;
const PRE = `${REPO_SH}/deployed/cardano/preview`;
const CKB_RPC = process.env.CKB_RPC || "https://testnet.ckb.dev";
const PREVIEW_KEY = process.env.CHIRAL_PREVIEW_KEY || "/mnt/c/Users/telmo/.chiral/preview_relayer.key";
const BURN_RECEIPT_CODE = process.env.XADA_BURN_RECEIPT_CODE
  || JSON.parse(fs.readFileSync(path.join(HERE, "xada_burn_deploy.json"), "utf8")).burnReceiptCode.codeHash;
const BURN_REDEEMER = `${CER}/xada_burn_return_redeemer.json`;    // per-burn proof (vk reused, proof fresh)
const fail = (m) => { console.log(JSON.stringify({ ok: false, error: String(m).slice(-500) })); process.exit(1); };
const q = (s) => `'${String(s).replace(/'/g, "'\\''")}'`;
const wsl = (script, env = "") => { const [c, a] = shInvoke(`export CHIRAL_PREVIEW_KEY=${PREVIEW_KEY} ${env} && ${script}`);
  return execFileSync(c, a, { encoding: "utf8", maxBuffer: 256 * 1024 * 1024 }); };
const K_MIN = 12, WIN = "WINDOW_DEPTH=6 CHIRAL_WINDOW_DEPTH=6 CHIRAL_K_MIN=12";

const burnTxid = (process.argv[2] || "").replace(/^0x/, "");
if (!/^[0-9a-f]{64}$/.test(burnTxid)) fail("usage: xada_burn_orchestrate.mjs <burnTxid>");

try {
  // 1) capture the burn body + offsets (and read the bound amount + recipient the proof will commit to).
  process.stderr.write("[ret] capturing burn body…\n");
  wsl(`cd ${q(RELAYER)} && python3 gen_xada_burn_body.py 0x${burnTxid} ${BURN_RECEIPT_CODE} --rpc ${q(CKB_RPC)} --out ${q(CER + "/xada_burn_live.json")}`);
  const live = JSON.parse(fs.readFileSync(path.resolve(HERE, "../../spike/ckb-to-cardano/circuit/ceremony_xada_burn/xada_burn_live.json"), "utf8"));
  const amount = Number(live.amount), recipient = live.recipient;          // 28-byte cardano payment cred
  process.stderr.write(`[ret] burn binds amount=${amount} recipient=${recipient.slice(0, 12)}…\n`);

  // 2) burn block height -> re-anchor tip = block + K_MIN (the proof's window/tip).
  const blk = Number(JSON.parse(wsl(`cd ${q(RELAYER)} && python3 -c "import json,urllib.request; r=json.load(urllib.request.urlopen(urllib.request.Request('${CKB_RPC}',data=json.dumps({'id':1,'jsonrpc':'2.0','method':'get_transaction','params':['0x${burnTxid}']}).encode(),headers={'content-type':'application/json','User-Agent':'chiral/1'}))); bh=r['result']['tx_status']['block_hash']; h=json.load(urllib.request.urlopen(urllib.request.Request('${CKB_RPC}',data=json.dumps({'id':1,'jsonrpc':'2.0','method':'get_header','params':[bh]}).encode(),headers={'content-type':'application/json','User-Agent':'chiral/1'}))); print(json.dumps({'n':int(h['result']['number'],16)}))"`).trim()).n);
  const tip = blk + K_MIN;
  process.stderr.write(`[ret] burn block ${blk}; re-anchoring checkpoint to tip ${tip}…\n`);

  // 3) re-anchor the checkpoint so its window covers the burn.
  wsl(`cd ${q(RELAYER)} && CHIRAL_WINDOW_DEPTH=6 python3 advance_relayer.py init ${CKB_RPC} ${tip} ${q(CER + "/reanchor.json")}`);
  const re = JSON.parse(fs.readFileSync(path.resolve(HERE, "../../spike/ckb-to-cardano/circuit/ceremony_xada_burn/reanchor.json"), "utf8"));
  const anchorEnv = `CHIRAL_CHAIN_ROOT=${re.chain_root} CHIRAL_WINDOW_ROOT=${re.window_root} CHIRAL_TIP_HEIGHT=${re.tip_height}`;
  let nft;
  if (process.env.CHIRAL_STABLE_REGISTRY) {
    // E2: re-anchor the ONE STABLE registry cell IN PLACE (governor-gated, monotonic tip) -> its NFT, and the
    // ada_escrow that bakes it, stay CONSTANT across returns. No per-return re-genesis / escrow churn.
    wsl(`cd ${q(G16)} && python3 ckpt_reanchor.py --live`, anchorEnv);
    nft = JSON.parse(fs.readFileSync(path.resolve(HERE, "../../deployed/cardano/preview/ckpt-registry.json"), "utf8")).registry_nft;
    process.stderr.write(`[ret] STABLE registry re-anchored: nft ${nft.slice(0, 12)}… tip ${tip}\n`);
  } else {
    // legacy: genesis a FRESH checkpoint NFT each return (churns the escrow + ref scripts ~190 ADA/return).
    wsl(`cd ${q(G16)} && python3 genesis_ckbcert.py --live`, anchorEnv);
    nft = JSON.parse(fs.readFileSync(path.resolve(HERE, "../../deployed/cardano/preview/ckbcert-genesis.json"), "utf8")).checkpoint_nft;
    process.stderr.write(`[ret] checkpoint re-anchored: nft ${nft.slice(0, 12)}… tip ${tip}\n`);
  }

  // 4) witness + window (at the SAME tip), then PROVE reusing the burn pk (fast).
  process.stderr.write("[ret] fetching witness/window + proving (reusing burn pk)…\n");
  wsl(`cd ${q(RELAYER)} && TARGET_TX=0x${burnTxid} TARGET_BLOCK=${blk} python3 relayer.py ${CKB_RPC} ${q(CER + "/xada_burn_wit.json")}`);
  wsl(`cd ${q(RELAYER)} && ${WIN} python3 relayer_window.py ${CKB_RPC} ${blk} ${q(CER + "/window.json")}`);
  // PROVE: prefer the WARM resident prover (the 480MB ceremony pk loaded ONCE -> ~8.5s/proof) if its socket is
  // up; else COLD-prove (reloads the pk, ~6-7 min). Start the warm service once with:
  //   CHIRAL_SERVE=/tmp/chiral_warm.sock CEREMONY_PK=<CER>/leap_bound_windowed_pk.bin WINDOW_DEPTH=6 \
  //     CHIRAL_K_MIN=12 circuit/prover/target/release/leap_bound_windowed &
  let warmOk = false;
  try {
    if (wsl(`cd ${q(RELAYER)} && python3 warm_prove.py up`).includes('"ready":true')) {
      const r = wsl(`cd ${q(RELAYER)} && python3 warm_prove.py prove ${q(CER + "/xada_burn_wit.json")} ${q(CER + "/xada_burn_live.json")} ${q(BURN_REDEEMER)} --window ${q(CER + "/window.json")} --depth 6 --k 12 --kmin 12`);
      warmOk = r.includes('"ok":true');
      if (warmOk) process.stderr.write(`[ret] WARM prover used (pk resident): ${r.trim()}\n`);
    }
  } catch (e) { /* fall through to cold */ }
  if (!warmOk) {
    process.stderr.write("[ret] warm prover unavailable; cold-proving (loads the 480MB pk, ~6-7 min)…\n");
    wsl(`cd ${q(REPO_SH + "/spike/ckb-to-cardano")} && CHIRAL_WINDOW=${q(CER + "/window.json")} ${WIN} K=12 PROVE=1 CEREMONY_PK=${q(CER + "/leap_bound_windowed_pk.bin")} circuit/prover/target/release/leap_bound_windowed ${q(CER + "/xada_burn_wit.json")} ${q(CER + "/xada_burn_live.json")} > ${q(BURN_REDEEMER)}`);
  }

  // 5) lock the return escrow (burn vk + new nft), recipient[:28] == the burn recipient, amount == burn amount.
  const recip32 = recipient.padEnd(64, "0");                               // escrow ckb_recipient[:28] = burn recip
  // CHIRAL_ESCROW_OUT/IN: keep the transient RETURN escrow in its OWN file so it never clobbers the static
  // FORWARD escrow config (xada-escrow.json) the dapp serves to testers for locking.
  const eenv = `CHIRAL_RETURN_VK=${q(BURN_REDEEMER)} CHIRAL_CHECKPOINT_NFT=${nft} CHIRAL_ESCROW_NO_OVERRIDE=1 CHIRAL_ESCROW_OUT=xada-return-escrow.json CHIRAL_XADA_RECIPIENT=${recip32} CHIRAL_XADA_AMOUNT=${amount} CHIRAL_XADA_NONCE=${blk}`;
  process.stderr.write("[ret] locking return escrow + releasing…\n");
  wsl(`cd ${q(G16)} && python3 escrow_lock.py --live`, eenv);

  // 6) deploy ref scripts for THIS escrow script + spend it via Release (verifies the proof on-chain).
  // CHIRAL_BURN_SEAL = THIS burn's tx hash (== the seal the prover committed as PI[1]); without it release_xada.py
  // falls back to a hardcoded default seal - which only happened to be correct for the very first return.
  // E2: the stable registry cell lives at the ckpt_registry address (not advance_ckbcert's), so release_xada
  // must look for the checkpoint reference cell there - CHIRAL_CKPT_SCRIPT points it at the registry script.
  const ckptScriptEnv = process.env.CHIRAL_STABLE_REGISTRY
    ? ` CHIRAL_CKPT_SCRIPT=${JSON.parse(fs.readFileSync(path.resolve(HERE, "../../deployed/cardano/preview/ckpt-registry.json"), "utf8")).registry_script}`
    : "";
  const renv = `CHIRAL_RETURN_VK=${q(BURN_REDEEMER)} CHIRAL_CHECKPOINT_NFT=${nft} CHIRAL_BURN_SEAL=${burnTxid} CHIRAL_ESCROW_IN=xada-return-escrow.json${ckptScriptEnv}`;
  wsl(`cd ${q(G16)} && python3 release_xada.py --refscripts`, renv);
  // poll until the ref-script tx confirms (was a blind `sleep 25`): break as soon as the ref UTxOs are live,
  // capped so a slow network still proceeds (the --live build re-checks and fails safe if a ref is missing).
  const refsDeadline = Date.now() + Number(process.env.CHIRAL_REFSCRIPT_WAIT_MS || 90000);
  let refsLive = false;
  while (Date.now() < refsDeadline) {
    try { wsl(`cd ${q(G16)} && python3 release_xada.py --check-refs`, renv); refsLive = true; break; }
    catch { wsl(`sleep 5`); }
  }
  if (!refsLive) process.stderr.write("[ret] ref scripts not confirmed within cap - attempting release anyway\n");
  const rel = wsl(`cd ${q(G16)} && python3 release_xada.py --live`, renv);
  const m = rel.match(/preview tx:\s*([0-9a-f]{64})/i);
  if (!m) fail("release produced no txid: " + rel.slice(-400));
  console.log(JSON.stringify({ ok: true, released: true, releaseTxid: m[1], releasedAda: amount / 1e6, recipient, burnTxid }));
} catch (e) {
  fail(e?.stderr || e?.message || e);
}
