#!/usr/bin/env bash
# AC4.4 final: wait until BoundState + ref scripts index (dry --leap resolves all cells + guard passes), then
# submit the live leap-mint of 200 chiCKB against the ADVANCED checkpoint (tip 21435564). Koios-retry-safe.
KEY=/mnt/c/Users/telmo/.chiral/preview_relayer.key
G=/mnt/c/Users/telmo/chiral-study/spike/ckb-to-cardano/groth16
cd "$G"
echo "== wait until BoundState + ref scripts index (dry --leap) =="
ready=0
for i in $(seq 1 40); do
  if CHIRAL_PREVIEW_KEY=$KEY python3 leap_mint.py --leap > /tmp/leapdry.log 2>&1; then
    if grep -qE "\[dry\] outputs" /tmp/leapdry.log; then echo "  cells ready"; grep -E "guard|bound_in" /tmp/leapdry.log; ready=1; break; fi
  fi
  echo "  try $i: not ready ($(grep -oE "missing a cell|Error[^ ]*|AssertionError|bound_in: [A-Za-z]+" /tmp/leapdry.log | tail -1))"; sleep 15
done
[ "$ready" = 1 ] || { echo "LEAP CELLS NEVER READY"; tail -5 /tmp/leapdry.log; exit 1; }
echo "== LEAP MINT (live, retry) =="
for try in 1 2 3 4; do
  CHIRAL_PREVIEW_KEY=$KEY python3 leap_mint.py --leap --live > /tmp/leaplive_$try.log 2>&1 || true
  tail -4 /tmp/leaplive_$try.log
  if grep -qE "LEAP MINT submitted" /tmp/leaplive_$try.log; then echo "LEAP_OK"; grep -E "LEAP MINT submitted" /tmp/leaplive_$try.log; exit 0; fi
  echo "  leap try $try incomplete; wait 20s"; sleep 20
done
echo "LEAP_FAILED"; exit 1
