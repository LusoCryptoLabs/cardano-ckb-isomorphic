#!/usr/bin/env python3
"""CKB->Cardano relayer (fetch stage): pull LIVE Pudge data and emit witness.json for the leap prover.
Fetches a recent confirmed block T + its 3 predecessors (to build a small checkpoint MMR), and a real
tx's CBMT proof in T. The Rust prover (relay_prove) derives the digests/paths and produces the Groth16
proof + the broadcast-ready Cardano redeemer. No light-client needed for the demo: the checkpoint MMR is
built from the fetched headers (in production the relayer fetches the canonical light-client MMR proof)."""
import urllib.request, json, sys, time, os
RPC = sys.argv[1] if len(sys.argv) > 1 else "https://testnet.ckb.dev"
def rpc(m, p):
    for a in range(5):
        try:
            req = urllib.request.Request(RPC, data=json.dumps({"id":1,"jsonrpc":"2.0","method":m,"params":p}).encode(),
                headers={"content-type":"application/json","User-Agent":"relayer/1"})
            r = json.load(urllib.request.urlopen(req, timeout=25))
            if r.get("error"): raise RuntimeError(r["error"])
            return r["result"]
        except Exception as e:
            if a==4: raise
            time.sleep(2*(a+1))
def hdr_fields(h):
    return {k:h[k] for k in ["compact_target","timestamp","number","epoch","parent_hash",
            "transactions_root","proposals_hash","extra_hash","dao","nonce","hash"]}

tip = int(rpc("get_tip_header", [])["number"], 16)
TARGET_TX = os.environ.get("TARGET_TX"); TARGET_BLOCK = os.environ.get("TARGET_BLOCK")
if TARGET_TX and not TARGET_BLOCK:
    # derive the confirmed block from the tx itself, so a caller need only supply TARGET_TX
    st = rpc("get_transaction", [TARGET_TX]); bh = (st.get("tx_status") or {}).get("block_hash")
    if bh: TARGET_BLOCK = str(int(rpc("get_header", [bh])["number"], 16))
if TARGET_TX and TARGET_BLOCK:
    # LIVE value-binding proof: prove on a SPECIFIC bridge-receipt tx in its block.
    T = int(TARGET_BLOCK); block = rpc("get_block_by_number", [hex(T)])
    txs = block["transactions"]; tx_idx = next(i for i, t in enumerate(txs) if t["hash"] == TARGET_TX)
else:
    T = tip - 20                                  # a comfortably-confirmed block
    for n in range(T, T-200, -1):                 # find a block with a non-cellbase tx (>=2 txs)
        b = rpc("get_block_by_number", [hex(n)])
        if len(b["transactions"]) >= 2: T = n; block = b; break
    txs = block["transactions"]; tx_idx = 1
hdrs = [hdr_fields(rpc("get_header_by_number", [hex(T-3+i)])) for i in range(4)]   # MMR leaves T-3..T
tx = txs[tx_idx]
proof = rpc("get_transaction_proof", [[tx["hash"]]])
seal = tx["inputs"][0]["previous_output"]      # a REAL single-use outpoint = the seal
witness = {
  "rpc": RPC, "tip": tip, "target_block": T,
  "headers": hdrs,                              # 4 consecutive: T-3..T (T is the proven leaf)
  "tx_hash": tx["hash"], "tx_index": tx_idx,
  "cbmt": {"indices": proof["proof"]["indices"], "lemmas": proof["proof"]["lemmas"],
           "witnesses_root": proof["witnesses_root"]},
  "transactions_root": hdrs[3]["transactions_root"],
  "seal": {"tx_hash": seal["tx_hash"], "index": seal["index"]},
}
json.dump(witness, open(sys.argv[2] if len(sys.argv)>2 else "/tmp/witness.json","w"), indent=1)
print(f"live witness: tip={tip} target_block={T} txs_in_block={len(txs)} tx={tx['hash'][:14]} seal={seal['tx_hash'][:14]}:{seal['index']}")
print(f"checkpoint MMR leaves: {[h['number'] for h in hdrs]}  transactions_root={hdrs[3]['transactions_root'][:16]}")
