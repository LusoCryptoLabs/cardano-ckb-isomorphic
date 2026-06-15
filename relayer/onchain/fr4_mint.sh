#!/usr/bin/env bash
# FR4.4: the live value-bound leap-mint against the redeployed leg.  --create then --leap --live.
export CHIRAL_PREVIEW_KEY=/mnt/c/Users/telmo/.chiral/preview_relayer.key
export AIKEN=/root/.aiken/bin/aiken
source ~/.cargo/env 2>/dev/null || true
cd /mnt/c/Users/telmo/chiral-study/spike/ckb-to-cardano/groth16
python3 leap_mint.py "$@"
