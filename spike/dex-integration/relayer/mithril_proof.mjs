// mithril_proof.mjs - the Cardano→CKB ProofProvider: turn a Mithril CardanoTransactions inclusion proof
// into the exact FINALIZE witness bytes the DEPLOYED `bound_asset_unified` verifier parses. The byte layout
// is read straight from that verifier's reader (spike/phase1/bound_asset_unified.rs, struct R):
//   lp(x)        = u32le(len) ‖ x
//   items(xs)    = u32le(count) ‖ for each: u32le(len) ‖ x
//   u64(n)       = 8-byte LE
//   witness      = lp(tx_body) ‖ lp(sub_root) ‖ u64(sub_pos) ‖ u64(sub_size) ‖ items(sub_items)
//                  ‖ lp(range_key) ‖ u64(master_pos) ‖ u64(master_size) ‖ items(master_items)
// The MMR math (two-level Blake2s256 MKMapProof) is already proven on real Mithril data in
// spike/{cross-chain,phase3}; this module is the on-demand ENCODER + the aggregator adapter that feeds it.

const toBytes = (x) => (x instanceof Uint8Array ? x : typeof x === "string" ? hexToBytes(x) : Uint8Array.from(x));
function hexToBytes(h) {
  const s = h.replace(/^0x/, "");
  const o = new Uint8Array(s.length / 2);
  for (let i = 0; i < o.length; i++) o[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  return o;
}
const u32le = (n) => { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n, true); return b; };
const u64le = (n) => { const b = new Uint8Array(8); new DataView(b.buffer).setBigUint64(0, BigInt(n), true); return b; };
function concat(arrs) {
  const len = arrs.reduce((a, x) => a + x.length, 0);
  const out = new Uint8Array(len);
  let o = 0; for (const a of arrs) { out.set(a, o); o += a.length; }
  return out;
}
const lp = (x) => { const b = toBytes(x); return concat([u32le(b.length), b]); };
const items = (xs) => concat([u32le(xs.length), ...xs.map((x) => lp(x))]);

/**
 * Encode a Mithril MKMapProof + tx body into the FINALIZE witness `bound_asset_unified` accepts.
 * @param {{ txBody, subRoot, subPos, subSize, subItems, rangeKey, masterPos, masterSize, masterItems }} p
 * @returns {Uint8Array}
 */
export function encodeFinalizeWitness(p) {
  return concat([
    lp(p.txBody),
    lp(p.subRoot), u64le(p.subPos), u64le(p.subSize), items(p.subItems.map(toBytes)),
    lp(p.rangeKey), u64le(p.masterPos), u64le(p.masterSize), items(p.masterItems.map(toBytes)),
  ]);
}

/** Inverse of encodeFinalizeWitness - mirrors the verifier's R reader, for round-trip validation. */
export function decodeFinalizeWitness(bytes) {
  let i = 0;
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const u32 = () => { const v = dv.getUint32(i, true); i += 4; return v; };
  const u64 = () => { const v = dv.getBigUint64(i, true); i += 8; return v; };
  const blob = () => { const n = u32(); const s = bytes.slice(i, i + n); i += n; return s; };
  const list = () => { const n = u32(); const out = []; for (let k = 0; k < n; k++) out.push(blob()); return out; };
  const txBody = blob();
  const subRoot = blob(), subPos = u64(), subSize = u64(), subItems = list();
  const rangeKey = blob(), masterPos = u64(), masterSize = u64(), masterItems = list();
  return { txBody, subRoot, subPos, subSize, subItems, rangeKey, masterPos, masterSize, masterItems, consumed: i };
}

/**
 * Adapter: map a Mithril aggregator's CardanoTransactions proof response to the encoder inputs. The real
 * endpoint is `GET {aggregator}/proof/cardano-transactions?transaction_hashes={txHash}` (Mithril
 * CardanoTransactions). The aggregator returns the certified tx-set proof; this pulls the two-level MMR
 * components out of it. Field paths are isolated here so they track the aggregator's response shape.
 */
export async function fetchCardanoTxProof(aggregatorUrl, txHash, txBodyHex, fetchImpl = fetch) {
  const url = `${aggregatorUrl.replace(/\/$/, "")}/proof/cardano-transactions?transaction_hashes=${txHash}`;
  const res = await fetchImpl(url);
  if (!res.ok) throw new Error(`mithril aggregator ${res.status}`);
  const j = await res.json();
  // certificate_hash + proof are returned; the MKMapProof components live under the proof object. The exact
  // JSON shape is aggregator-version-specific, so this is the single place to map it -> encoder inputs.
  const pr = j.certified_transactions?.[0]?.proof ?? j.proof;
  if (!pr) throw new Error("no proof in aggregator response (map fetchCardanoTxProof to your aggregator version)");
  return {
    txBody: hexToBytes(txBodyHex),
    subRoot: pr.sub_root, subPos: pr.sub_pos, subSize: pr.sub_size, subItems: pr.sub_items,
    rangeKey: pr.range_key, masterPos: pr.master_pos, masterSize: pr.master_size, masterItems: pr.master_items,
  };
}

/** The ProofProvider for the Cardano→CKB direction (the FINALIZE witness). */
export function mithrilProvider({ aggregatorUrl, resolveProofComponents }) {
  return {
    async proveCardanoToCkb(event) {
      // resolveProofComponents(event) -> the MKMapProof components (from fetchCardanoTxProof or a local
      // certified set). Kept injectable so the relayer can use a live aggregator or captured certs.
      const components = await resolveProofComponents(event, { aggregatorUrl, fetchCardanoTxProof });
      return encodeFinalizeWitness(components);
    },
  };
}
