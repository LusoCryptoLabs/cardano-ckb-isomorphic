#!/usr/bin/env bash
set -e
cd /mnt/c/Users/telmo/chiral-study/relayer
python3.12 produce_witness.py 26a5228f127ac444d531752ff1d170648054da0cc65d5760cec5595376b31cee > onchain/bg_release_wit.json
echo "produce_witness root: $(python3.12 -c "import json;print(json.load(open('onchain/bg_release_wit.json'))['root'])")"
python3.12 reg_null_burn.py onchain/bg_release_wit.json onchain/registry_state.json 0x7ca6f10fccaf22d35e53aed7b6337cf1c23b8aba3c44f8673c00b1904373858a
echo BG_PROOFS_DONE
