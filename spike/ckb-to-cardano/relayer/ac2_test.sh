#!/usr/bin/env bash
# AC2 end-to-end: anchor from real CKB testnet headers, advance two real consecutive blocks, confirm the
# advance_live circuit accepts each real (state, header) and the relayer state chains correctly.
set -e
REL=/mnt/c/Users/telmo/chiral-study/spike/ckb-to-cardano/relayer
BIN=/mnt/c/Users/telmo/chiral-study/spike/ckb-to-cardano/circuit/prover/target/release/advance_live
RPC=https://testnet.ckb.dev
cd "$REL"
TIP=$(python3 advance_relayer.py tip "$RPC")
H0=$((TIP-100))
echo "== tip=$TIP  anchor H0=$H0 =="
python3 advance_relayer.py init $RPC $H0 /tmp/st0.json
python3 advance_relayer.py step $RPC /tmp/st0.json /tmp/step1.json
echo "-- advance 1 (circuit accepts real header $((H0+1))?) --"
CHIRAL_ADVANCE_STATE=/tmp/st0.json CHIRAL_ADVANCE_STEP=/tmp/step1.json COUNT_ONLY=1 "$BIN" 2>&1 | grep ADVANCE_LIVE
python3 advance_relayer.py apply /tmp/st0.json /tmp/step1.json /tmp/st1.json
python3 advance_relayer.py step $RPC /tmp/st1.json /tmp/step2.json
echo "-- advance 2 (circuit accepts real header $((H0+2)) from the chained state?) --"
CHIRAL_ADVANCE_STATE=/tmp/st1.json CHIRAL_ADVANCE_STEP=/tmp/step2.json COUNT_ONLY=1 "$BIN" 2>&1 | grep ADVANCE_LIVE
echo "-- chain check: st1.chain_root must equal step2.header.parent_hash --"
python3 -c "import json; s=json.load(open('/tmp/st1.json')); p=json.load(open('/tmp/step2.json'))['header']['parent_hash'][2:]; print('CHAINED' if s['chain_root']==p else 'BROKEN', s['chain_root'][:16], p[:16])"
echo "AC2_TEST_DONE"
