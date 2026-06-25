#!/usr/bin/env bash
# AC4.3a (offline, parallel with the cascade): pre-generate the 12 advance proofs chaining R -> R+12.
# Each: relayer step (next real header) + prove (ceremony pk) + cross-check (SNARK==native) + native apply to
# the next state. Saves redeemer_N.json so the submit phase can spend the checkpoint 12x in order.
set -e
source ~/.cargo/env 2>/dev/null || true
RPC=https://testnet.ckb.dev
REL=/mnt/c/Users/telmo/chiral-study/spike/ckb-to-cardano/relayer
P=/mnt/c/Users/telmo/chiral-study/spike/ckb-to-cardano/circuit/prover
CER=/mnt/c/Users/telmo/chiral-study/spike/ckb-to-cardano/circuit/ceremony
ST=$REL/advance-state.json
DIR=$REL/ac4_advances
rm -rf "$DIR"; mkdir -p "$DIR"
PK=$CER/advance_live_pk.bin
for N in $(seq 1 12); do
  STEP=$DIR/step_$N.json
  RED=$DIR/redeemer_$N.json
  cd "$REL"; python3 advance_relayer.py step $RPC "$ST" "$STEP"
  cd "$P"; PROVE=1 CEREMONY_PK="$PK" CHIRAL_ADVANCE_STATE="$ST" CHIRAL_ADVANCE_STEP="$STEP" \
    ./target/release/advance_live > "$RED" 2> /tmp/adv_$N.log
  grep -q "arkworks verify = true" /tmp/adv_$N.log || { echo "PROVE $N FAILED"; tail -4 /tmp/adv_$N.log; exit 1; }
  cd "$REL"; python3 advance_relayer.py check "$ST" "$STEP" "$RED" > /dev/null
  python3 advance_relayer.py apply "$ST" "$STEP" "$DIR/state_$N.json"; cp "$DIR/state_$N.json" "$ST"
  echo "  advance $N proved+chained -> tip $(python3 -c "import json;print(json.load(open('$ST'))['tip_height'])")"
done
echo "AC4_PROOFS_DONE: 12 advance redeemers in $DIR (state now $(python3 -c "import json;print(json.load(open('$ST'))['tip_height'])"))"
