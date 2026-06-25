// cardano_keygen.mjs - generate a fresh Cardano PREVIEW payment key for the relayer/leap testing,
// and print its address to fund. The private key (bech32 ed25519_sk) is written OUTSIDE the repo
// (~/.chiral/) mode 600, never echoed, so it can't be committed or captured. Won't overwrite.
//
//   node cardano_keygen.mjs          # generate (refuses if key file exists)
//   node cardano_keygen.mjs --show   # print the address/vkh of the EXISTING key
//
// The emitted bech32 key feeds Lucid/MeshJS directly (selectWallet.fromPrivateKey / RELAYER_CARDANO_KEY).
import CSL from "@emurgo/cardano-serialization-lib-nodejs";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const DIR = path.join(os.homedir(), ".chiral");
const KEY_PATH = path.join(DIR, "preview_relayer.key");
const TESTNET = 0; // network id: testnet/preview = 0, mainnet = 1
const show = process.argv.includes("--show");

function addressOf(skBech) {
  const sk = CSL.PrivateKey.from_bech32(skBech);
  const vkh = sk.to_public().hash();                              // blake2b-224 payment key hash
  const cred = CSL.Credential.from_keyhash(vkh);
  const addr = CSL.EnterpriseAddress.new(TESTNET, cred).to_address().to_bech32(); // addr_test1...
  return { addr, vkh: Buffer.from(vkh.to_bytes()).toString("hex") };
}

if (show) {
  if (!fs.existsSync(KEY_PATH)) { console.error(`no key at ${KEY_PATH}`); process.exit(1); }
  const { addr, vkh } = addressOf(fs.readFileSync(KEY_PATH, "utf8").trim());
  console.log(JSON.stringify({ keyFile: KEY_PATH, network: "cardano-preview", address: addr, payment_vkh: vkh }, null, 2));
  process.exit(0);
}

if (fs.existsSync(KEY_PATH)) {
  console.error(`refusing to overwrite existing key at ${KEY_PATH} (use --show to see its address)`);
  process.exit(1);
}

fs.mkdirSync(DIR, { recursive: true });
const sk = CSL.PrivateKey.generate_ed25519();
const skBech = sk.to_bech32();
const { addr, vkh } = addressOf(skBech);
fs.writeFileSync(KEY_PATH, skBech, { mode: 0o600 });
try { fs.chmodSync(KEY_PATH, 0o600); } catch {}

console.log(JSON.stringify({
  generated: true,
  keyFile: KEY_PATH,
  network: "cardano-preview",
  address: addr,                 // <-- FUND THIS at the Cardano preview faucet
  payment_vkh: vkh,
  faucet: "https://docs.cardano.org/cardano-testnets/tools/faucet/  (network: Preview)",
  note: "bech32 ed25519_sk saved to keyFile, mode 600, OUTSIDE the repo. Never commit it. " +
        "Feed Lucid/MeshJS via RELAYER_CARDANO_KEY=$(cat " + KEY_PATH + ").",
}, null, 2));
