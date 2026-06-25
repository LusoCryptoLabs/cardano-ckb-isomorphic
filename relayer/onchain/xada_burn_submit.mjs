// xada_burn_submit.mjs <userSignedTxHex> - finish the self-serve χADA burn: the user already signed THEIR χADA
// input in the browser; the relayer now signs the funding input (its own secp group - independent of the user's,
// so the user's witness is preserved) and submits. Prints {burnTxid}. The receipt cell lands at burnTxid:0.
import { ccc } from "@ckb-ccc/core";
import { signerOf, wait } from "./_signer.mjs";

const out = (o) => { console.log(JSON.stringify(o)); process.exit(o.error ? 1 : 0); };
const hex = process.argv[2];
if (!/^0x[0-9a-f]+$/i.test(hex || "")) out({ error: "usage: xada_burn_submit.mjs <userSignedTxHex>" });

const { client, signer } = signerOf();
let tx;
try { tx = ccc.Transaction.fromBytes(ccc.bytesFrom(hex)); } catch (e) { out({ error: "bad tx hex: " + e.message }); }
let h;
try {
  const signed = await signer.signTransaction(tx);           // signs ONLY the relayer's funding group
  h = await client.sendTransaction(signed);
} catch (e) { out({ error: "burn submit rejected: " + String(e?.message || e).slice(-400) }); }
await wait(client, h);
out({ ok: true, burnTxid: h, receiptCell: h + ":0" });
