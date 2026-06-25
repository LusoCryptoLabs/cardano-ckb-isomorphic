#!/usr/bin/env bash
# AC3d (offline half): step the relayer to the next real header, prove the advance with the CEREMONY pk
# (proof under the baked vk), and cross-check the SNARK new_state == relayer native_next. No Cardano spend.
set -e
source ~/.cargo/env 2>/dev/null || true
RPC=https://testnet.ckb.dev
REL=/mnt/c/Users/telmo/chiral-study/spike/ckb-to-cardano/relayer
P=/mnt/c/Users/telmo/chiral-study/spike/ckb-to-cardano/circuit/prover
CER=/mnt/c/Users/telmo/chiral-study/spike/ckb-to-cardano/circuit/ceremony
ST=$REL/advance-state.json
STEP=$REL/advance-step.json
RED=$CER/advance_live_live_redeemer.json
cd "$REL"
python3 advance_relayer.py step $RPC "$ST" "$STEP"
cd "$P"
echo "== proving advance (ceremony pk, ~1-2 min) =="
PROVE=1 CEREMONY_PK="$CER/advance_live_pk.bin" CHIRAL_ADVANCE_STATE="$ST" CHIRAL_ADVANCE_STEP="$STEP" \
  ./target/release/advance_live > "$RED" 2> /tmp/ac3d_prove.log
grep -E "arkworks verify|old_root=|tip=" /tmp/ac3d_prove.log
cd "$REL"
python3 advance_relayer.py check "$ST" "$STEP" "$RED"
echo "AC3D_PROVE_DONE -> $RED"
