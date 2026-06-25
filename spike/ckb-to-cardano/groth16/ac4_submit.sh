#!/usr/bin/env bash
# AC4.3b: submit the 12 pre-generated advance txs SEQUENTIALLY, idempotent + Koios-retry-safe. Each spends the
# prior continuing checkpoint; poll for the new tip to index before the next. Brings lock R=21435552 to K_MIN depth.
KEY=/mnt/c/Users/telmo/.chiral/preview_relayer.key
G=/mnt/c/Users/telmo/chiral-study/spike/ckb-to-cardano/groth16
DIR=/mnt/c/Users/telmo/chiral-study/spike/ckb-to-cardano/relayer/ac4_advances
R=21435552
cd "$G"
tip() { CHIRAL_PREVIEW_KEY=$KEY python3 query_checkpoint_tip.py 2>/dev/null || echo ERR; }
for N in $(seq 1 12); do
  TGT=$((R+N)); PREV=$((R+N-1))
  echo "== advance $N: $PREV -> $TGT =="
  ok=0
  for try in 1 2 3 4 5; do
    CUR=$(tip)
    if [ "$CUR" = "$TGT" ]; then echo "  already at $TGT"; ok=1; break; fi
    if [ "$CUR" != "$PREV" ]; then echo "  tip=$CUR (want $PREV), wait 15s"; sleep 15; continue; fi
    CHIRAL_PREVIEW_KEY=$KEY python3 advance_tx.py "$DIR/redeemer_$N.json" --live 2>&1 | grep -E "ADVANCE submitted|guard|Error|assert" | head -2
    for i in $(seq 1 30); do CUR=$(tip); [ "$CUR" = "$TGT" ] && break; sleep 10; done
    if [ "$CUR" = "$TGT" ]; then echo "  confirmed tip=$TGT"; ok=1; break; fi
    echo "  try $try did not confirm (tip=$CUR); retry"
  done
  [ "$ok" = 1 ] || { echo "ADVANCE $N FAILED after retries (tip=$(tip))"; exit 1; }
done
echo "AC4_SUBMIT_DONE: checkpoint advanced to tip $((R+12)) (lock R=$R now at depth 12 = K_MIN)"
