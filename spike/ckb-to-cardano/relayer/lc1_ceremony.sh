#!/usr/bin/env bash
# LC1: FRESH leap ceremony. The existing leap_bound_windowed_pk.bin was stale (arkworks verify=false, older
# circuit). Run a real MPC ceremony over the CURRENT leap circuit -> a ceremony leap vk (toxic waste destroyed)
# to close the seeded-vk forge hole. ~40 min (2^21, phase-1 PoT + phase-2 delta, 3+3 contributors).
set -e
RPC=https://testnet.ckb.dev
RELAYER=/mnt/c/Users/telmo/chiral-study/spike/ckb-to-cardano/relayer
PROV=/mnt/c/Users/telmo/chiral-study/spike/ckb-to-cardano/circuit/prover
ONCHAIN=/mnt/c/Users/telmo/chiral-study/relayer/onchain
CER=/mnt/c/Users/telmo/chiral-study/spike/ckb-to-cardano/circuit/ceremony
LOCK_TX=0xe86b1ceffa985264defbd099ce76af43c187c7ea5448eb919206094324314318
R=21435552
cd "$RELAYER"
TARGET_TX=$LOCK_TX TARGET_BLOCK=$R python3 relayer.py $RPC /tmp/wit_v.json >/dev/null
CHIRAL_WINDOW_DEPTH=6 CHIRAL_K_MIN=12 python3 relayer_window.py $RPC $R /tmp/win_v.json >/dev/null
cd "$PROV"
echo "== fresh leap ceremony (CEREMONY_OUT) =="
CEREMONY_OUT="$CER" PROVE=1 WINDOW_DEPTH=6 CHIRAL_K_MIN=12 K=12 CHIRAL_WINDOW=/tmp/win_v.json \
  ./target/release/leap_bound_windowed /tmp/wit_v.json "$ONCHAIN/bridge_lock_live.json" \
  > "$CER/leap_ceremony_redeemer.json" 2> "$CER/leap_ceremony2.log"
echo "CEREMONY_EXIT=$?"
tail -6 "$CER/leap_ceremony2.log"
ls -la "$CER/leap_bound_windowed_pk.bin" 2>/dev/null
python3 -c "
import json
d=json.load(open('$CER/leap_ceremony_redeemer.json'))
a=d['vk']['alpha_g1']
print('vk.alpha:', a[:20], ('SEEDED (failed)' if a.startswith('b14be0b3') else 'CEREMONY (forge-safe)'), '| ic len', len(d['vk']['ic']))
"
