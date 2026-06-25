// release_orchestrate.mjs <burnTxid> <receiptTxid> <ckbRecipient> - drive the keyless reverse-leg release
// end to end (the pipeline proven live as 0xcaf514b0…0x0bfabccc), so /api/leap/release is push-button.
// Steps: cert gate (gen_cert_witness + produce_witness) -> advance the AVK light-client to the burn's epoch
// if stale -> publish the LCKP at the burn root -> insert the replay-once nullifier -> bg_release (keyless,
// to the tester's address). No key authorizes the receipt spend; the relayer only submits + pays fees.
// Mixed runtime: python steps run in WSL (transcode/Mithril), the on-chain .mjs steps run here (ccc + key).
// Prints a single JSON result line on stdout.
import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { REPO_SH, shInvoke } from "./_rt.mjs";   // WSL (this box) vs native-Linux (VPS)

const HERE = path.dirname(fileURLToPath(import.meta.url));
const J = (f) => JSON.parse(fs.readFileSync(path.join(HERE, f), "utf8"));
const REPO_WSL = REPO_SH;                          // repo path as the shell/python see it (WSL or native)
const [burnTxid, receiptTxid, ckbRecipient] = process.argv.slice(2);
const fail = (msg) => { console.log(JSON.stringify({ ok: false, error: msg })); process.exit(1); };
if (!/^[0-9a-f]{64}$/i.test(burnTxid || "")) fail("burnTxid must be 64-hex");
if (!/^0x[0-9a-f]{64}$/i.test(receiptTxid || "")) fail("receiptTxid must be 0x32-byte");
if (!ckbRecipient) fail("ckbRecipient required");

// run a bash pipeline (WSL on this box / native bash on a Linux VPS); return stdout. sh-quote for safety.
const q = (s) => `'${String(s).replace(/'/g, "'\\''")}'`;
const wsl = (script) => { const [c, a] = shInvoke(script); return execFileSync(c, a, { encoding: "utf8" }); };
// run a Windows-side .mjs (ccc + the funded relayer key) in this dir; inherit stdio so we see progress.
const node = (script, env = {}) => execFileSync("node", [script], { cwd: HERE, encoding: "utf8", env: { ...process.env, ...env }, stdio: ["ignore", "pipe", "inherit"] });
const lastJson = (s) => JSON.parse(s.slice(s.lastIndexOf("{")));

try {
  // 1) cert gate - cert witness (LCKP) + MKMapProof (receipt spend). Either returns wait-certification.
  const cw = lastJson(wsl(`cd ${q(REPO_WSL + "/relayer")} && python3 gen_cert_witness.py ${q(burnTxid)} onchain/bg_ctwit.json`));
  if (cw.status !== "ready") { console.log(JSON.stringify({ ok: true, certified: false, status: cw.status })); process.exit(0); }
  const pw = lastJson(wsl(`cd ${q(REPO_WSL + "/relayer")} && python3 produce_witness.py ${q(burnTxid)} | tee onchain/bg_release_wit.json`));
  if (pw.status !== "ready") { console.log(JSON.stringify({ ok: true, certified: false, status: pw.status })); process.exit(0); }
  const burnEpoch = Number(cw.epoch);

  // 2) advance the AVK light-client to the burn's epoch (one Mithril epoch per roll)
  let avkEpoch = Number(J("chain_state.json").ckpt.epoch);
  while (avkEpoch < burnEpoch) {
    wsl(`cd ${q(REPO_WSL + "/relayer/onchain")} && python3 gen_advance.py ${avkEpoch} advance.json`);
    node("advance_epoch.mjs");
    avkEpoch = Number(J("chain_state.json").ckpt.epoch);
  }

  // 3) publish the LCKP at the burn's certified root (verifies against the now-current AVK)
  node("bg_refresh.mjs");

  // 4) point the release at the tester's receipt, insert the replay-once nullifier against the live root
  fs.writeFileSync(path.join(HERE, "bg_receipt.json"),
    JSON.stringify({ txHash: receiptTxid, index: 0, burnGatedCodeHash: J("burn_gated_live.json").burn_gated_code_hash }, null, 2));
  const liveRoot = J("boundasset_v2_state.json").registry.root;
  wsl(`cd ${q(REPO_WSL + "/relayer")} && python3 reg_null_burn.py onchain/bg_release_wit.json onchain/registry_state.json ${q(liveRoot)}`);

  // 5) keyless release to the tester (bg_release also advances registry_state + the live registry pointer)
  node("bg_release.mjs", { CKB_RECIPIENT: ckbRecipient });
  const rel = J("bg_release.json");
  console.log(JSON.stringify({ ok: true, certified: true, releaseTxid: rel.releaseTx, releasedCKB: rel.releasedCKB, recipient: ckbRecipient }));
} catch (e) {
  fail(String(e?.stderr || e?.message || e).slice(-700));
}
