// get_osmo_recipient.mjs — derive the Osmosis deployer's bech32 address and its 20-byte account id (what the
// CKB-side xosmo_burn_receipt commits as the release recipient). Prints PUBLIC info only; never the key.
import { DirectSecp256k1HdWallet } from "@cosmjs/proto-signing";
import { fromBech32 } from "@cosmjs/encoding";
import fs from "node:fs"; import os from "node:os"; import path from "node:path";

const KEYFILE = path.join(os.homedir(), ".chiral", "osmo_testnet_deployer.key");
const wallet = await DirectSecp256k1HdWallet.fromMnemonic(fs.readFileSync(KEYFILE, "utf8").trim(), { prefix: "osmo" });
const [acct] = await wallet.getAccounts();
const { prefix, data } = fromBech32(acct.address);
const hex20 = Buffer.from(data).toString("hex");
console.log(JSON.stringify({ address: acct.address, prefix, account20: hex20, len: data.length }));
fs.writeFileSync(new URL("./osmo_recipient.json", import.meta.url), JSON.stringify({ address: acct.address, account20: hex20 }, null, 2));
