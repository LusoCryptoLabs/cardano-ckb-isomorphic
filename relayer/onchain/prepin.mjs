import fs from "node:fs"; import path from "node:path"; import { fileURLToPath } from "node:url";
const HERE = path.dirname(fileURLToPath(import.meta.url));
const PIN = JSON.parse(fs.readFileSync(path.join(HERE, "cv_pin_state.json"), "utf8"));
const dPath = path.join(HERE, "deployed.json"), csPath = path.join(HERE, "chain_state.json");
// backups
fs.copyFileSync(dPath, dPath + ".bak-prepin");
fs.copyFileSync(csPath, csPath + ".bak-1326");
// repoint deployed.json cv_advance + cv_deploy at the NEW pinned cells (keep old in .bak)
const D = JSON.parse(fs.readFileSync(dPath, "utf8"));
D.cv_advance = { txHash: PIN.cv_advance_deploy.txHash, index: 0, codeHash: PIN.new_cv_advance_codeHash, size: PIN.cv_advance_deploy.size };
D.cv_deploy  = { txHash: PIN.cv_deploy_deploy.txHash,  index: 0, codeHash: PIN.new_cv_deploy_codeHash,  size: PIN.cv_deploy_deploy.size };
fs.writeFileSync(dPath, JSON.stringify(D, null, 2));
// reset chain_state so lc_chain re-genesizes under the new cv_advance
fs.writeFileSync(csPath, JSON.stringify({}, null, 2));
console.log("deployed.json cv_advance ->", D.cv_advance.codeHash, "@", D.cv_advance.txHash);
console.log("deployed.json cv_deploy  ->", D.cv_deploy.codeHash, "@", D.cv_deploy.txHash);
console.log("chain_state.json reset (backed up to .bak-1326). deployed.json backed up to .bak-prepin");
