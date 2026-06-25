// relayer.mjs - bridge relayer skeleton. Watches one chain for a leap, asks a ProofProvider for the witness
// the OTHER chain's (already-deployed) verifier needs, then submits the mint/burn there. The proving
// backends (Mithril/BoundAsset for CKB-side, Groth16 for Cardano-side) are external and plug in via the
// ProofProvider interface - this file is the wiring + event parsing, validated end-to-end except the proofs.
//
// KEY SAFETY: submit keys come from env at runtime and are never stored.
//   RELAYER_CKB_KEY=0x...  RELAYER_CARDANO_KEY=...  node relayer.mjs

const U128_MAX = (1n << 128n) - 1n;

// ---- the normalized leap event (same MAPPING_SPEC encoding as the guard + UI) ----
/** @typedef {{ dir: "ckb_to_cardano"|"cardano_to_ckb", amount: bigint, recipient: string, nonce: string, srcTx: string }} LeapEvent */

/** decode the financial state amount (first 16 bytes, LE) - matches decode_amount_le / decodeU128le. */
export function decodeAmountLe(bytes) {
  if (bytes.length < 16) throw new Error("state too short for u128 amount");
  let v = 0n;
  for (let i = 15; i >= 0; i--) v = (v << 8n) | BigInt(bytes[i]);
  if (v > U128_MAX) throw new Error("amount out of u128 range");
  return v;
}

/** Parse a CKB bound-cell (seal32 ‖ idx4 ‖ amount16 ‖ recipient32) into a leap-out event. */
export function parseCkbBound(seal, dataBytes) {
  if (dataBytes.length < 36 + 16 + 32) throw new Error("bound cell too short");
  const amount = decodeAmountLe(dataBytes.slice(36, 52));
  const recipient = Buffer.from(dataBytes.slice(52, 84)).toString("hex");
  return { dir: "ckb_to_cardano", amount, recipient, nonce: seal, srcTx: seal };
}

// ---- the proving backend interface (the external, heavy part) ----
/**
 * @typedef {Object} ProofProvider
 * @property {(e: LeapEvent) => Promise<Uint8Array>} proveCkbToCardano  Groth16 of CKB consensus + the leap
 * @property {(e: LeapEvent) => Promise<Uint8Array>} proveCardanoToCkb  Mithril/BoundAsset proof
 */

/** A stub provider: lets you validate watch→submit wiring before the real provers are connected. */
export const stubProvider = {
  async proveCkbToCardano(e) { throw new Error(`connect a Groth16 prover (leap ${e.amount} -> ${e.recipient})`); },
  async proveCardanoToCkb(e) { throw new Error(`connect a Mithril/BoundAsset prover (leap ${e.amount} -> ${e.recipient})`); },
};

import { mithrilProvider } from "./mithril_proof.mjs";
import { groth16Provider } from "./groth16_prover.mjs";

/** Compose the REAL providers: Groth16 (CKB→Cardano) + Mithril FINALIZE witness (Cardano→CKB). */
export function makeProvider({ groth16, mithril }) {
  const g = groth16Provider(groth16 ?? {});
  const m = mithrilProvider(mithril ?? { resolveProofComponents: async () => { throw new Error("set mithril.resolveProofComponents"); } });
  return {
    proveCkbToCardano: (e) => g.proveCkbToCardano(e),
    proveCardanoToCkb: (e) => m.proveCardanoToCkb(e),
  };
}

// ---- submitters (build + sign + broadcast on the destination chain) ----
import { buildFinalizeLeapOut } from "./ckb_leap.mjs";
import { buildLeapInMintPlan } from "./cardano_leap.mjs";

// CKB leap-out (FINALIZE + burn): build the complete tx with the verifier's required shape, then sign+send.
// `cfg` carries the deployed out-points (from deploy_ckb.mjs) + the user's bound cell + the bridge owner cell.
async function submitToCkb(event, witness, cfg) {
  if (!cfg?.client) { console.log(`[submit:ckb] would finalize-burn ${event.amount} (${witness.length}B proof) - wire cfg.client + deployed out-points`); return; }
  const { ccc } = await import("@ckb-ccc/core");
  const tx = await buildFinalizeLeapOut({
    client: cfg.client, xudtType: cfg.xudtType, userLock: cfg.userLock, amount: event.amount,
    boundCell: cfg.boundCell, ownerCell: cfg.ownerCell, finalizeWitness: witness, deps: cfg.deps,
  });
  const signer = new ccc.SignerCkbPrivateKey(cfg.client, process.env.RELAYER_CKB_KEY);
  await tx.completeFeeBy(signer);
  return signer.sendTransaction(tx);
}

// Cardano leap-in (FT mint via leap_mint_guard): build the lib-agnostic plan, then serialize+sign with your
// Cardano lib. `cfg` carries policyId / ftName / addresses / the policy reference UTxO (from deploy_cardano).
async function submitToCardano(event, witness, cfg) {
  const plan = buildLeapInMintPlan({
    policyId: cfg?.policyId, ftNameAscii: cfg?.ftNameAscii, amount: event.amount,
    recipientAddr: cfg?.recipientAddr, recipientCredHex: event.recipient, ckbSealHex: event.nonce,
    boundScriptAddr: cfg?.boundScriptAddr, policyRefUtxo: cfg?.policyRefUtxo, groth16Proof: witness,
  });
  console.log(`[submit:cardano] leap-in mint plan ready: ${event.amount} to ${event.recipient}`);
  return plan; // hand to Lucid/MeshJS to serialize + sign with RELAYER_CARDANO_KEY
}

/** One leap, end to end: prove on the source, submit on the destination. `cfg` carries the deployed
 *  out-points / addresses / cells (from deploy_ckb.mjs + deploy_cardano.md) the submitters need. */
export async function handleLeap(event, provider, cfg = {}) {
  if (event.amount <= 0n || event.amount > U128_MAX) throw new Error("invalid amount");
  if (event.dir === "ckb_to_cardano") {
    const witness = await provider.proveCkbToCardano(event);
    return submitToCardano(event, witness, cfg.cardano);
  } else {
    const witness = await provider.proveCardanoToCkb(event);
    return submitToCkb(event, witness, cfg.ckb);
  }
}

// ---- the watch loop (skeleton) ----
async function main() {
  const provider = stubProvider; // TODO: swap in the real Mithril + Groth16 providers
  console.error("relayer up. Watching for leaps… (stub provider: logs the witness it would request)");
  console.error("CKB key set:", !!process.env.RELAYER_CKB_KEY, "| Cardano key set:", !!process.env.RELAYER_CARDANO_KEY);
  // TODO: subscribe to Pudge (BoundAsset cell creations) + Preview (cardano_bound transitions), normalize to
  // LeapEvent (parseCkbBound / the Cardano analogue), then handleLeap(event, provider). Durable replay state
  // + idempotency go here. For now, validate the pieces above with the exported parsers/handlers in tests.
  if (process.argv.includes("--selftest")) {
    const seal = "0x" + "11".repeat(32);
    const data = new Uint8Array(84);
    // amount = 52_000_000 at offset 36, recipient = 0x07.. at 52
    let a = 52_000_000n; for (let i = 0; i < 16; i++) { data[36 + i] = Number(a & 0xffn); a >>= 8n; }
    data.fill(7, 52, 84);
    const ev = parseCkbBound(seal, data);
    console.log("selftest event:", { ...ev, amount: ev.amount.toString() });
    try { await handleLeap(ev, provider); } catch (e) { console.log("expected (no prover):", e.message); }
  }
}

if (import.meta.url === `file://${process.argv[1]}`) main().catch((e) => { console.error(e); process.exit(1); });
