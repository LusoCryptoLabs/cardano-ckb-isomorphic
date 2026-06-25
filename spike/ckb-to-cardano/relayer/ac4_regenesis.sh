#!/usr/bin/env bash
# AC4.2: re-genesis the checkpoint anchored at a SPECIFIC H0 (the fresh lock's height), so the lock sits at the
# genesis tip (depth 0) and 12 advances bring it to K_MIN depth. Pass H0 as $1, and "live" as $2 to submit.
set -e
source ~/.cargo/env 2>/dev/null || true
H0=$1
RPC=https://testnet.ckb.dev
REL=/mnt/c/Users/telmo/chiral-study/spike/ckb-to-cardano/relayer
G=/mnt/c/Users/telmo/chiral-study/spike/ckb-to-cardano/groth16
ST=$REL/advance-state.json
KEY=/mnt/c/Users/telmo/.chiral/preview_relayer.key
cd "$REL"
echo "== re-anchor at lock height H0=$H0 =="
python3 advance_relayer.py init $RPC "$H0" "$ST"
CR=$(python3 -c "import json;print(json.load(open('$ST'))['chain_root'])")
WR=$(python3 -c "import json;print(json.load(open('$ST'))['window_root'])")
TH=$(python3 -c "import json;print(json.load(open('$ST'))['tip_height'])")
echo "anchor: chain_root=$CR window_root=$WR tip=$TH"
cd "$G"
FLAG=""; [ "$2" = "live" ] && FLAG="--live"
CHIRAL_CHAIN_ROOT=$CR CHIRAL_WINDOW_ROOT=$WR CHIRAL_TIP_HEIGHT=$TH CHIRAL_PREVIEW_KEY=$KEY \
  python3 genesis_ckbcert.py $FLAG 2>&1 | tail -14
