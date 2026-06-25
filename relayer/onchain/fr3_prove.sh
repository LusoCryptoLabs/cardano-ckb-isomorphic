#!/usr/bin/env bash
# FR3: build the witness for the sample lock + run leap_bound_windowed PROVE=1 to mint the fresh forward-leg VK
# (seeded test setup -> deterministic vk) baked to the new bridge code 0x48548a94. Output: fr_redeemer.json.
set -e
PROV=/mnt/c/Users/telmo/chiral-study/spike/ckb-to-cardano/circuit/prover
RELAYER=/mnt/c/Users/telmo/chiral-study/spike/ckb-to-cardano/relayer
ONCHAIN=/mnt/c/Users/telmo/chiral-study/relayer/onchain
TX=0x77ded628c8a08d640ca95a45939039cb77d58b739e5ab93143685a7674b81c88
BLK=21432975
RPC=https://testnet.ckb.dev

cd "$RELAYER"
echo "[witness] relayer.py for $TX @ $BLK"
TARGET_TX=$TX TARGET_BLOCK=$BLK python3 relayer.py "$RPC" /tmp/witness_fr.json
echo "[window] waiting until tip >= $((BLK+12)) ..."
until python3 relayer_window.py "$RPC" $BLK /tmp/window_fr.json 2>/tmp/win_err; do
  echo "  not deep enough; retry in 20s"; sleep 20
done
echo "[prove] leap_bound_windowed PROVE=1 (fresh VK for bridge 0x48548a94) ..."
cd "$PROV"
PROVE=1 WINDOW_DEPTH=6 CHIRAL_K_MIN=12 K=12 CHIRAL_WINDOW=/tmp/window_fr.json \
  EVENT_OUT="$ONCHAIN/fr_event.json" \
  cargo run --release --bin leap_bound_windowed /tmp/witness_fr.json "$ONCHAIN/bridge_lock_live.json" \
  > "$ONCHAIN/fr_redeemer.json" 2>/tmp/fr_prove.log
echo "PROVE_DONE exit=$?"
tail -8 /tmp/fr_prove.log
