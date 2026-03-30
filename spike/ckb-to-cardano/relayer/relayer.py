#!/usr/bin/env python3
"""CKB->Cardano relayer (fetch stage): pull LIVE Pudge data and emit witness.json for the leap prover.
Fetches a recent confirmed block T + its 3 predecessors (to build a small checkpoint MMR), and a real
tx's CBMT proof in T. The Rust prover (relay_prove) derives the digests/paths and produces the Groth16
proof + the broadcast-ready Cardano redeemer. No light-client needed for the demo: the checkpoint MMR is
built from the fetched headers (in production the relayer fetches the canonical light-client MMR proof)."""
import urllib.request, json, sys, time
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
T = tip - 20                                  # a comfortably-confirmed block
# find a block at/just below T that has a non-cellbase tx (>=2 txs) for a meaningful CBMT path
for n in range(T, T-200, -1):
    b = rpc("get_block_by_number", [hex(n)])
    if len(b["transactions"]) >= 2: T = n; block = b; break
hdrs = [hdr_fields(rpc("get_header_by_number", [hex(T-3+i)])) for i in range(4)]   # MMR leaves T-3..T
txs = block["transactions"]; tx_idx = 1                                            # a real non-cellbase tx
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
