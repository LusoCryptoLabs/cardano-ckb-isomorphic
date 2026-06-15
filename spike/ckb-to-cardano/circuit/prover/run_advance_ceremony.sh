#!/usr/bin/env bash
# AC3a: MPC trusted-setup ceremony for advance_live -> production vk + pk (toxic waste destroyed; a seeded vk
# would let anyone forge advances). Writes advance_live_pk.bin + transcript + the ceremony redeemer (prod vk).
set -e
CER=/mnt/c/Users/telmo/chiral-study/spike/ckb-to-cardano/circuit/ceremony
cd /mnt/c/Users/telmo/chiral-study/spike/ckb-to-cardano/circuit/prover
CEREMONY_OUT="$CER" PROVE=1 ./target/release/advance_live > "$CER/advance_live_ceremony_redeemer.json" 2> "$CER/advance_live_ceremony.log"
echo "CEREMONY_EXIT=$?"
tail -8 "$CER/advance_live_ceremony.log"
ls -la "$CER/advance_live_pk.bin" 2>/dev/null || echo "NO PK"
echo "--- redeemer vk ic length ---"
python3 -c "import json; print(len(json.load(open('$CER/advance_live_ceremony_redeemer.json'))['vk']['ic']))"
