// xada.js - native ADA → CKB leg (the browser half), the symmetric mirror of mint.js (CKB → Cardano).
//
// The user locks real preview ADA at the deployed `ada_escrow` with an inline EscrowDatum that binds the lock
// to THEIR OWN CKB wallet (ckb_recipient = their CKB lock hash). They sign it in their Cardano wallet - true
// self-custody; the relayer never touches their ADA. Once Mithril certifies that lock, the relayer mints χADA
// (a real xUDT) to that exact CKB lock - and the deployed xada_mint_owner lock enforces in-VM that the mint
// goes nowhere else and is 1:1 with the locked lovelace, so the relayer cannot redirect or inflate it.
// Lazy-load the heavy Lucid/Cardano-multiplatform WASM (~4.4MB) only when the user builds a Cardano tx
// (lock / burn), not on first paint. Memoized - every call after the first reuses the one module instance.
import { jsonHeaders } from "./api.js";

let _lucidMod = null;
const lucidMod = () => (_lucidMod ??= import("@lucid-evolution/lucid"));

const noPfx = (h) => String(h || "").replace(/^0x/, "");

export async function fetchXadaConfig() {
  const r = await fetch("/api/xada/config");
  if (!r.ok) throw new Error("xada config unavailable");
  return r.json();
}

// Lucid against the backend-supplied Cardano provider (same provider the χCKB leg uses) + the CIP-30 wallet.
async function lucidFor(cardanoApi, bridgeCfg) {
  const p = bridgeCfg?.cardano;
  if (!p?.blockfrostUrl || !p?.blockfrostProjectId) throw new Error("backend did not supply a Cardano provider");
  const { Lucid, Blockfrost } = await lucidMod();
  const lucid = await Lucid(new Blockfrost(p.blockfrostUrl, p.blockfrostProjectId), p.network || "Preview");
  lucid.selectWallet.fromAPI(cardanoApi);
  return lucid;
}

// Build + sign + submit the ADA escrow-lock in the user's wallet. Returns the Cardano tx hash.
//   EscrowDatum = Constr 0 [ ckb_recipient: bytes32, amount: lovelace, nonce ]   (the relayer reads this to mint)
// The whole locked value IS `amount` (the owner lock checks datum.amount == the output's lovelace == χADA minted).
export async function lockAda({ cardanoApi, bridgeCfg, xcfg, amountAda, ckbRecipientHash, nonce }) {
  if (!xcfg?.escrowAddress) throw new Error("backend did not surface the escrow address");
  const recip = noPfx(ckbRecipientHash);
  if (!/^[0-9a-f]{64}$/.test(recip)) throw new Error("CKB recipient must be a 32-byte lock hash - connect your CKB wallet first");
  const ada = Number(amountAda);
  const lo = xcfg.minAda || 2, hi = xcfg.demoMaxAda || 5;
  if (!(ada >= lo && ada <= hi)) throw new Error(`lock between ${lo} and ${hi} ADA (placeholder-vk escrow → experiment cap)`);
  const lovelace = BigInt(Math.round(ada * 1e6));
  const { Data, Constr } = await lucidMod();
  const datum = Data.to(new Constr(0, [recip, lovelace, BigInt(nonce ?? Date.now())]));
  const lucid = await lucidFor(cardanoApi, bridgeCfg);
  const tx = await lucid.newTx()
    .pay.ToContract(xcfg.escrowAddress, { kind: "inline", value: datum }, { lovelace })
    .complete();
  const signed = await tx.sign.withWallet().complete();
  return await signed.submit();
}

// Ask the relayer to mint χADA against the (Mithril-certified) escrow lock. Returns {certified:false,…} while
// the aggregator is still certifying (the dApp retries), else {minted, mintTxid, tokenId, amount, recipient, …}.
export async function requestXadaMint({ escrowTxid, amountLovelace, recipientLock }) {
  const r = await fetch("/api/xada/mint", {
    method: "POST", headers: jsonHeaders(),
    body: JSON.stringify({ escrowTxid, amountLovelace, recipientLock }),
  });
  const j = await r.json();
  if (!r.ok || j.error) throw new Error(j.error || `mint failed (${r.status})`);
  return j;
}

// χADA → ADA RETURN: against a confirmed CKB χADA-burn tx, the relayer captures it, re-anchors the CKB-header
// checkpoint, proves the burn (reusing the burn key), and spends the ada_escrow.Release (on-chain Groth16
// verify) to pay the locked ADA to the burn's bound Cardano recipient. Returns {released, releaseTxid,
// releasedAda, recipient}. Heavy + slow (a few minutes - it re-anchors the checkpoint per return).
export async function requestXadaReturn({ burnTxid }) {
  const r = await fetch("/api/xada/return", {
    method: "POST", headers: jsonHeaders(),
    body: JSON.stringify({ burnTxid }),
  });
  const j = await r.json();
  if (!r.ok || j.error) throw new Error(j.error || `return failed (${r.status})`);
  return j;
}

// One-click χADA burn (co-signed): step 1 - the relayer builds the unsigned burn tx (adds the owner authority
// cell + funding). Returns { txHex, burnAmount, recipient }. The browser then signs the χADA input + submits.
export async function buildXadaBurn({ recipientLock, amount, cardanoRecipient }) {
  const r = await fetch("/api/xada/burn/build", {
    method: "POST", headers: jsonHeaders(),
    body: JSON.stringify({ recipientLock, amount, cardanoRecipient }),
  });
  const j = await r.json();
  if (!r.ok || j.error) throw new Error(j.error || `burn build failed (${r.status})`);
  return j;
}
// step 2 - the user signed their χADA input in the browser; the relayer signs funding + submits. Returns {burnTxid}.
export async function submitXadaBurn({ signedTxHex }) {
  const r = await fetch("/api/xada/burn/submit", {
    method: "POST", headers: jsonHeaders(),
    body: JSON.stringify({ signedTxHex }),
  });
  const j = await r.json();
  if (!r.ok || j.error) throw new Error(j.error || `burn submit failed (${r.status})`);
  return j;
}
