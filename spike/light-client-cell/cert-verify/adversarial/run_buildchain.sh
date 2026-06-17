#!/usr/bin/env bash
source ~/.cargo/env 2>/dev/null || true
export PATH="$PATH:/root/.cargo/bin"
export EXPORT=/tmp/chain_pinned
export TO_EPOCH=1331
cd /mnt/c/Users/telmo/chiral-study/spike/light-client-cell/cert-verify/adversarial
python3 build_chain_pinned.py 2>&1 | tail -30
