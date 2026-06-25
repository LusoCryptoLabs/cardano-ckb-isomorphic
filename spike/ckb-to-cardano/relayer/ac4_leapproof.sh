#!/usr/bin/env bash
# AC4.4a: regenerate the leap proof for the NEW lock (e86b1cef @ R=21435552) bound to the ADVANCED window
# (tip R+12=21435564, receipt R at depth K_MIN=12), seeded leap vk (matches the baked cardano_bound vk).
set -e
RPC=https://testnet.ckb.dev
RELAYER=/mnt/c/Users/telmo/chiral-study/spike/ckb-to-cardano/relayer
PROV=/mnt/c/Users/telmo/chiral-study/spike/ckb-to-cardano/circuit/prover
ONCHAIN=/mnt/c/Users/telmo/chiral-study/relayer/onchain
CER=/mnt/c/Users/telmo/chiral-study/spike/ckb-to-cardano/circuit/ceremony
LOCK_TX=0xe86b1ceffa985264defbd099ce76af43c187c7ea5448eb919206094324314318
R=21435552
echo "== 1) witness for the lock tx =="
cd "$RELAYER"
TARGET_TX=$LOCK_TX TARGET_BLOCK=$R python3 relayer.py $RPC /tmp/witness_leap.json
echo "== 2) window at tip R+12 (receipt R at depth K_MIN) =="
CHIRAL_WINDOW_DEPTH=6 CHIRAL_K_MIN=12 python3 relayer_window.py $RPC $R /tmp/window_leap.json
echo "== 3) prove leap (seeded vk) bound to the new window =="
cd "$PROV"
PROVE=1 WINDOW_DEPTH=6 CHIRAL_K_MIN=12 K=12 CHIRAL_WINDOW=/tmp/window_leap.json \
  ./target/release/leap_bound_windowed /tmp/witness_leap.json "$ONCHAIN/bridge_lock_live.json" \
  > "$CER/leap_bound_windowed_redeemer.json" 2> /tmp/leap_prove.log
grep -E "arkworks verify|BOUND_WINDOWED_LEAP_OK|audit. ALL" /tmp/leap_prove.log | tail -3
echo "AC4_LEAPPROOF_DONE -> $CER/leap_bound_windowed_redeemer.json"
