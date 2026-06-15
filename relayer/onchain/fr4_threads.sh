#!/usr/bin/env bash
# FR4.3: deploy the seal + policy + ratelimit thread singletons on preview and derive cardano_bound +
# leap_mint_guard against the new VK + new checkpoint.
export CHIRAL_PREVIEW_KEY=/mnt/c/Users/telmo/.chiral/preview_relayer.key
export AIKEN=/root/.aiken/bin/aiken
source ~/.cargo/env 2>/dev/null || true
cd /mnt/c/Users/telmo/chiral-study/spike/ckb-to-cardano/groth16
python3 genesis_threads.py "$@"
