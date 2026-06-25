#!/usr/bin/env bash
# FR4.2: deploy the ckbcert checkpoint on Cardano preview, pinned to the new proof's window_root + tip.
export CHIRAL_PREVIEW_KEY=/mnt/c/Users/telmo/.chiral/preview_relayer.key
export AIKEN=/root/.aiken/bin/aiken
export CHIRAL_WINDOW_ROOT=b6eef0ae098f26079b12ea988842518d1e5c4e63f026ff59ad58302b7522c147
export CHIRAL_TIP_HEIGHT=21432987
source ~/.cargo/env 2>/dev/null || true
cd /mnt/c/Users/telmo/chiral-study/spike/ckb-to-cardano/groth16
python3 genesis_ckbcert.py "$@"
