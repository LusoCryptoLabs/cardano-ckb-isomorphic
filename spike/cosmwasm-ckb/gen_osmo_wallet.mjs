// gen_osmo_wallet.mjs — generate (or load) the Osmosis testnet deployer wallet for the live CosmWasm deploy of
// the ckb-verifier contract. The mnemonic is written to ~/.chiral/osmo_testnet_deployer.key (mode 0600) and is
// NEVER printed. Idempotent: if the key file exists it is loaded, so re-running only re-prints the address.
//   chain: osmo-test-5   prefix: osmo   path: m/44'/118'/0'/0/0
//   faucet: https://faucet.testnet.osmosis.zone/   (up to 100 OSMO/day per address)
import { DirectSecp256k1HdWallet } from "@cosmjs/proto-signing";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const KEYDIR = path.join(os.homedir(), ".chiral");
const KEYFILE = path.join(KEYDIR, "osmo_testnet_deployer.key");
fs.mkdirSync(KEYDIR, { recursive: true });

let wallet;
if (fs.existsSync(KEYFILE)) {
  const mnemonic = fs.readFileSync(KEYFILE, "utf8").trim();
  wallet = await DirectSecp256k1HdWallet.fromMnemonic(mnemonic, { prefix: "osmo" });
} else {
  wallet = await DirectSecp256k1HdWallet.generate(24, { prefix: "osmo" });
  fs.writeFileSync(KEYFILE, wallet.mnemonic, { mode: 0o600 });
  console.log("generated a new deployer wallet");
}
const [acct] = await wallet.getAccounts();
console.log("osmo address:", acct.address);
console.log("key file    :", KEYFILE, "(mnemonic only, gitignored, never printed)");
console.log("faucet      : https://faucet.testnet.osmosis.zone/");
