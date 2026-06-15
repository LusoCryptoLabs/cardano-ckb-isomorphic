#!/usr/bin/env bash
# AC4.2 cascade (retry wrapper): genesis f12f66eb is already indexed; re-derive cardano_bound + leap_mint_guard
# from checkpoint 750093f5 by minting the 3 threads. Koios is flaky -> retry up to 5x until it fully completes.
KEY=/mnt/c/Users/telmo/.chiral/preview_relayer.key
G=/mnt/c/Users/telmo/chiral-study/spike/ckb-to-cardano/groth16
cd "$G"
for attempt in 1 2 3 4 5; do
  echo "== cascade attempt $attempt =="
  CHIRAL_PREVIEW_KEY=$KEY python3 genesis_threads.py --live > /tmp/cascade_$attempt.log 2>&1 || true
  tail -6 /tmp/cascade_$attempt.log
  if grep -q "ALL 3 thread genesis live" /tmp/cascade_$attempt.log; then
    echo "CASCADE_OK"; grep -E "cardano_bound:|leap_mint_guard:" /tmp/cascade_$attempt.log | tail -1; exit 0
  fi
  echo "  attempt $attempt incomplete; retry in 20s"; sleep 20
done
echo "CASCADE_FAILED after 5 attempts"; exit 1
