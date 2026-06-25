// mint.js - increments 3-4 of the self-custody leap (the browser half of CKB -> Cardano).
//
// Step 2 (prove): wait for the CKB lock to confirm, then ask the backend's proof service to turn it into a
// value-bound Groth16 redeemer (the backend holds NO keys; it only proves).
// Step 3 (mint): build + sign + submit the Cardano mint with the user's own CIP-30 wallet via Lucid. The
// χCKB minting policy is gated by the proof, not a signature, so the user signs it themselves - true
// self-custody. The minted amount is whatever the proof bound (== the locked CKB), so conservation holds.
// Lazy-load the heavy Lucid/Cardano-multiplatform WASM (~4.4MB) - only when the user actually builds a
// Cardano tx, not on first paint. Memoized so every call after the first reuses the one module instance.
import { jsonHeaders } from "./api.js";

let _lucidMod = null;
const lucidMod = () => (_lucidMod ??= import("@lucid-evolution/lucid"));

// init Lucid against the backend-supplied Cardano provider + the connected CIP-30 wallet.
async function lucidFor(cardanoApi, cfg) {
  const p = cfg?.cardano;
  if (!p?.blockfrostUrl || !p?.blockfrostProjectId) throw new Error("backend did not supply a Cardano provider");
  const { Lucid, Blockfrost } = await lucidMod();
  const lucid = await Lucid(new Blockfrost(p.blockfrostUrl, p.blockfrostProjectId), p.network || "Preview");
  lucid.selectWallet.fromAPI(cardanoApi);
  return lucid;
}

// Poll the CKB lock tx until it is committed in a block (the proof needs a confirmed block).
export async function waitLockConfirmed(ckbClient, txid, { tries = 60, gapMs = 4000, onTick } = {}) {
  for (let i = 0; i < tries; i++) {
    let status = "unknown";
    try { status = (await ckbClient.getTransaction(txid))?.status || "unknown"; } catch { /* keep polling */ }
    onTick?.(status, i);
    if (status === "committed") return true;
    if (status === "rejected") throw new Error("lock tx was rejected by the CKB network");
    await new Promise((r) => setTimeout(r, gapMs));
  }
  throw new Error("lock tx not confirmed in time (still pending) - try the prove step again shortly");
}

// Ask the backend to prove the confirmed lock. Returns the mint params the wallet needs.
export async function requestProof(lockTxid) {
  const r = await fetch("/api/leap/prove", {
    method: "POST", headers: jsonHeaders(), body: JSON.stringify({ lockTxid }),
  });
  const j = await r.json();
  if (!r.ok || j.error) throw new Error(j.error || `prove failed (${r.status})`);
  return j; // { redeemer_cbor, mint_script_hex, policy_id, asset_name_hex, qty, amount, recipient, commitment }
}

// Build + sign + submit the χCKB mint in the user's CIP-30 wallet. Returns the Cardano tx hash.
export async function mintChiCKB({ cardanoApi, cardano, cfg, mintParams }) {
  const lucid = await lucidFor(cardanoApi, cfg);
  const { applyDoubleCborEncoding, mintingPolicyToId } = await lucidMod();

  // the minting policy = the deployed zk_chiral_mint Plutus script; its id MUST match the proof's policy_id.
  const policy = { type: "PlutusV3", script: applyDoubleCborEncoding(mintParams.mint_script_hex) };
  const policyId = mintingPolicyToId(policy);
  if (policyId !== mintParams.policy_id) {
    throw new Error(`policy id mismatch (script ${policyId} vs proof ${mintParams.policy_id}) - wrong plutus.json?`);
  }
  // the proof binds the recipient credential; mint to the SAME wallet that locked, or the policy rejects it.
  const recip = String(mintParams.recipient || "").replace(/^0x/, "");
  const bound = (cardano?.addressHex || "").replace(/^0x/, "").slice(2, 2 + 56);
  if (recip && bound && recip !== bound) {
    throw new Error("connected Cardano wallet differs from the address you locked to - connect the original wallet");
  }

  const unit = mintParams.policy_id + mintParams.asset_name_hex;
  const qty = BigInt(mintParams.qty);
  const addr = await lucid.wallet().address();
  const tx = await lucid.newTx()
    .mintAssets({ [unit]: qty }, mintParams.redeemer_cbor)   // redeemer = the Plutus-Data CBOR the backend emitted
    .attach.MintingPolicy(policy)
    .pay.ToAddress(addr, { [unit]: qty })                   // the minted χCKB lands in the user's own wallet
    .complete();
  const signed = await tx.sign.withWallet().complete();
  return await signed.submit();
}

// Reverse leg, Cardano half: BURN `qty` χCKB. The policy allows any pure burn (no proof), so we attach a
// well-formed but dummy MintRedeemer - is_pure_burn short-circuits to True. Returns the burn tx hash, which
// the relayer then proves Mithril-certified to release the locked CKB on the CKB side.
export async function burnChiCKB({ cardanoApi, cfg, qty }) {
  const scriptHex = cfg?.cardano?.mintScriptHex;
  const bg = cfg?.burnGated;
  if (!scriptHex || !bg?.policyId) throw new Error("backend did not surface the χCKB policy (mintScriptHex/policyId)");
  const lucid = await lucidFor(cardanoApi, cfg);
  const { applyDoubleCborEncoding, Data, Constr } = await lucidMod();
  const policy = { type: "PlutusV3", script: applyDoubleCborEncoding(scriptHex) };
  const unit = bg.policyId + bg.assetNameHex;
  // dummy MintRedeemer { proof: {a,b,c}, public_inputs: [], state: "", seal: "" } - unused on the burn path.
  const dummy = Data.to(new Constr(0, [new Constr(0, ["", "", ""]), [], "", ""]));
  const tx = await lucid.newTx()
    .mintAssets({ [unit]: -BigInt(qty) }, dummy)   // negative mint = burn
    .attach.MintingPolicy(policy)
    .complete();
  const signed = await tx.sign.withWallet().complete();
  return await signed.submit();
}

// Ask the backend to release the locked CKB against a confirmed χCKB burn (Mithril-certified, in CKB-VM).
// Returns the CKB release tx hash. The backend holds NO key that authorizes the receipt - only the certified
// burn + the replay-once nullifier do.
export async function requestRelease(burnTxid, receiptTxid, ckbRecipient) {
  const r = await fetch("/api/leap/release", {
    method: "POST", headers: jsonHeaders(),
    body: JSON.stringify({ burnTxid, receiptTxid, ckbRecipient }),
  });
  const j = await r.json();
  if (!r.ok || j.error) throw new Error(j.error || `release failed (${r.status})`);
  return j; // {certified:false,...} while awaiting cert, else {released, releaseTxid, releasedCKB}
}
