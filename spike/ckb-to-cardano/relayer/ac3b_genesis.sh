#!/usr/bin/env bash
# AC3b: anchor the relayer at a recent CKB height, then re-genesis the checkpoint with the advance ceremony vk
# + the real anchor (chain_root=anchor tip hash, window_root, tip). Pass "live" as $1 to actually submit.
set -e
source ~/.cargo/env 2>/dev/null || true
RPC=https://testnet.ckb.dev
REL=/mnt/c/Users/telmo/chiral-study/spike/ckb-to-cardano/relayer
G=/mnt/c/Users/telmo/chiral-study/spike/ckb-to-cardano/groth16
ST=$REL/advance-state.json
KEY=/mnt/c/Users/telmo/.chiral/preview_relayer.key
cd "$REL"
if [ "$1" != "live" ] || [ ! -f "$ST" ]; then
  TIP=$(python3 advance_relayer.py tip $RPC)
  H0=$((TIP-20))
  echo "== anchoring at H0=$H0 (tip=$TIP) =="
  python3 advance_relayer.py init $RPC $H0 "$ST"
fi
CR=$(python3 -c "import json;print(json.load(open('$ST'))['chain_root'])")
WR=$(python3 -c "import json;print(json.load(open('$ST'))['window_root'])")
TH=$(python3 -c "import json;print(json.load(open('$ST'))['tip_height'])")
echo "anchor: chain_root=$CR  window_root=$WR  tip=$TH"
cd "$G"
FLAG=""; [ "$1" = "live" ] && FLAG="--live"
CHIRAL_CHAIN_ROOT=$CR CHIRAL_WINDOW_ROOT=$WR CHIRAL_TIP_HEIGHT=$TH CHIRAL_PREVIEW_KEY=$KEY \
  python3 genesis_ckbcert.py $FLAG 2>&1 | tail -14
