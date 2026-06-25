import fs from "node:fs"; import path from "node:path"; import { fileURLToPath } from "node:url";
const HERE = path.dirname(fileURLToPath(import.meta.url));
const PIN = JSON.parse(fs.readFileSync(path.join(HERE, "cv_pin_state.json"), "utf8"));
const cs = JSON.parse(fs.readFileSync(path.join(HERE, "chain_state.json"), "utf8"));
// 1) new checkpoint_v2.json (the LCKP the leap path reads) - back up old
const cpPath = path.join(HERE, "checkpoint_v2.json");
fs.copyFileSync(cpPath, cpPath + ".bak-prepin");
const newCp = {
  checkpoint: { txHash: cs.deploy.txHash, index: 0 },
  root: cs.deploy.root, height: String(cs.deploy.height), data: cs.deploy.checkpointData,
  witnessCell: cs.witness,
  lckpTypeHash: PIN.new_CHIRAL_LCKP_TH,
  avkCheckpoint: { txHash: cs.ckpt.outpoint.txHash, index: 0, epoch: cs.ckpt.epoch },
  cvDeployCodeHash: PIN.new_cv_deploy_codeHash, cvAdvanceCodeHash: PIN.new_cv_advance_codeHash,
  note: "STM-pinned + singleton-guarded cv_* lineage (Gate 1). LCKP under new cv_deploy 0x52bdcbcb; AVK under new cv_advance 0x97c650d0.",
};
fs.writeFileSync(cpPath, JSON.stringify(newCp, null, 2));
// 2) deployed.json: bound_asset -> new bound_asset_v2; record old (to-reclaim) under *_superseded
const dPath = path.join(HERE, "deployed.json");
const D = JSON.parse(fs.readFileSync(dPath, "utf8"));
D.bound_asset_superseded = D.bound_asset; D.cv_deploy_v2_superseded = D.cv_deploy_v2;
D.bound_asset_v2 = { txHash: PIN.bound_asset_v2_deploy.txHash, index: 0, codeHash: PIN.new_bound_asset_v2_codeHash, size: PIN.bound_asset_v2_deploy.size,
  lckpTypeHash: PIN.new_CHIRAL_LCKP_TH };
fs.writeFileSync(dPath, JSON.stringify(D, null, 2));
console.log("checkpoint_v2.json -> new LCKP", newCp.checkpoint.txHash, "type", newCp.lckpTypeHash);
console.log("  AVK @ epoch", newCp.avkCheckpoint.epoch, newCp.avkCheckpoint.txHash);
console.log("deployed.json bound_asset_v2 ->", D.bound_asset_v2.codeHash);
