#!/usr/bin/env bash
# LC0: verify the existing leap ceremony pk (leap_bound_windowed_pk.bin) matches the CURRENT leap circuit.
# Prove a leap under CEREMONY_PK and check: it loads, arkworks verify = true, and the vk is the ceremony vk
# (alpha != the seeded b14be0b3). If so, the forge-hole re-bake is contained (no fresh ceremony needed).
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
echo "== prove leap under CEREMONY_PK =="
PROVE=1 CEREMONY_PK="$CER/leap_bound_windowed_pk.bin" WINDOW_DEPTH=6 CHIRAL_K_MIN=12 K=12 CHIRAL_WINDOW=/tmp/win_v.json \
  ./target/release/leap_bound_windowed /tmp/wit_v.json "$ONCHAIN/bridge_lock_live.json" > /tmp/leap_cer_red.json 2> /tmp/leap_cer.log
grep -E "loading ceremony|arkworks verify" /tmp/leap_cer.log
python3 -c "
import json
d=json.load(open('/tmp/leap_cer_red.json'))
a=d['vk']['alpha_g1']
print('vk.alpha:', a[:20])
print('VERDICT:', 'CEREMONY (different toxic waste, forge-safe)' if not a.startswith('b14be0b3') else 'STILL SEEDED (ceremony pk did not take)')
print('ic len:', len(d['vk']['ic']), '(leap = 6)')
"
