// keygen.mjs - generate a fresh CKB Pudge (testnet) signer for the relayer, and print its address
// to fund. The private key is written OUTSIDE the repo (~/.chiral/) with no echo to stdout, so it
// can never be committed or captured in a transcript. Re-running will NOT overwrite an existing key.
//
//   node keygen.mjs            # generate (refuses if key file already exists)
//   node keygen.mjs --show     # print the address of the EXISTING key (no generation)
//
import { ccc } from "@ckb-ccc/core";
import { randomBytes } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const DIR = path.join(os.homedir(), ".chiral");
const KEY_PATH = path.join(DIR, "pudge_relayer.key");
const show = process.argv.includes("--show");

async function addressOf(privHex) {
  const client = new ccc.ClientPublicTestnet(); // Pudge
  const signer = new ccc.SignerCkbPrivateKey(client, privHex);
  const addr = await signer.getRecommendedAddress();
  const lock = (await signer.getAddressObjs())[0].script;
  return { addr, lockHash: lock.hash() };
}

if (show) {
  if (!fs.existsSync(KEY_PATH)) { console.error(`no key at ${KEY_PATH}`); process.exit(1); }
  const priv = fs.readFileSync(KEY_PATH, "utf8").trim();
  const { addr, lockHash } = await addressOf(priv);
  console.log(JSON.stringify({ keyFile: KEY_PATH, network: "ckb-pudge", address: addr, lockHash }, null, 2));
  process.exit(0);
}

if (fs.existsSync(KEY_PATH)) {
  console.error(`refusing to overwrite existing key at ${KEY_PATH} (use --show to see its address)`);
  process.exit(1);
}

fs.mkdirSync(DIR, { recursive: true });
const priv = "0x" + randomBytes(32).toString("hex");
const { addr, lockHash } = await addressOf(priv);
fs.writeFileSync(KEY_PATH, priv, { mode: 0o600 });
try { fs.chmodSync(KEY_PATH, 0o600); } catch {}

console.log(JSON.stringify({
  generated: true,
  keyFile: KEY_PATH,
  network: "ckb-pudge",
  address: addr,                 // <-- FUND THIS at the Pudge faucet
  lockHash,
  faucet: "https://faucet.nervos.org/  (select Testnet/Pudge, paste the address)",
  note: "private key saved to keyFile, mode 600, OUTSIDE the repo. Never commit it. " +
        "Point the relayer at it with RELAYER_KEY=" + KEY_PATH,
}, null, 2));
