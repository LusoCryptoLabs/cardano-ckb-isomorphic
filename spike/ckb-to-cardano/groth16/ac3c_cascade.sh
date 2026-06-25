#!/usr/bin/env bash
# AC3c: wait for the re-genesis tx (edf01c1f) to index (its gref 2bac1437#4 spent), then run the LIVE cascade
# (genesis_threads --live) re-deriving cardano_bound + leap_mint_guard from the NEW checkpoint NFT.
set -e
KEY=/mnt/c/Users/telmo/.chiral/preview_relayer.key
G=/mnt/c/Users/telmo/chiral-study/spike/ckb-to-cardano/groth16
BIND=/mnt/c/Users/telmo/chiral-study/cardano/binding
cd "$G"
echo "== waiting for genesis edf01c1f to index (gref 2bac1437#4 spent) =="
for i in $(seq 1 40); do
  R=$(CHIRAL_PREVIEW_KEY=$KEY python3 - <<PY 2>/dev/null
import sys
sys.path.insert(0, "$G"); sys.path.insert(0, "$BIND")
import cardano_net
ctx = cardano_net.chain_context(); sk, vk, a = cardano_net.account()
gone = not any(str(u.input.transaction_id) == "2bac14373c71ecf66712c09dd3363fdfd60c55190592b2ef13183a603148658e" and u.input.index == 4 for u in ctx.utxos(str(a)))
print("INDEXED" if gone else "PENDING")
PY
)
  echo "  poll $i: ${R:-ERR}"
  [ "$R" = "INDEXED" ] && break
  sleep 15
done
echo "== live cascade: genesis_threads --live =="
CHIRAL_PREVIEW_KEY=$KEY python3 genesis_threads.py --live 2>&1 | tail -22
