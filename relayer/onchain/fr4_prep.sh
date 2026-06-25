#!/usr/bin/env bash
# FR4.1: inject the fresh forward-leg VK into the ceremony (so the Cardano deploy derives against it) and
# recover the proof's raw window_root + tip (the values the ckbcert checkpoint must pin).
set -e
CER=/mnt/c/Users/telmo/chiral-study/spike/ckb-to-cardano/circuit/ceremony
ONCHAIN=/mnt/c/Users/telmo/chiral-study/relayer/onchain
[ -f "$CER/leap_bound_windowed_redeemer.json" ] && cp "$CER/leap_bound_windowed_redeemer.json" "$CER/leap_bound_windowed_redeemer.OLD.json" || true
cp "$ONCHAIN/fr_redeemer.json" "$CER/leap_bound_windowed_redeemer.json"
echo "injected fresh VK -> ceremony/leap_bound_windowed_redeemer.json (old -> .OLD.json)"
python3 - <<'PY'
import json, hashlib
def h(d): return hashlib.blake2b(d, digest_size=32, person=b'ckb-default-hash').digest()
w = json.load(open('/tmp/window_fr.json'))
lv = [bytes.fromhex(x.replace('0x','')) for x in w['leaves']]
while len(lv) > 1:
    lv = [h(lv[i]+lv[i+1]) for i in range(0, len(lv), 2)]
print('WINDOW_ROOT', lv[0].hex())
print('TIP_HEIGHT', w['tip_height'])
print('RECEIPT_HEIGHT', w['receipt_height'])
PY
