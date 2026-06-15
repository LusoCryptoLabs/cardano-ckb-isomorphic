#!/usr/bin/env bash
# AC2 full prove on REAL live data + cross-check: advance_live's emitted new_state must equal the relayer's
# native next state (so the on-chain checkpoint the SNARK authorizes == what the relayer tracks off-chain).
set -e
REL=/mnt/c/Users/telmo/chiral-study/spike/ckb-to-cardano/relayer
BIN=/mnt/c/Users/telmo/chiral-study/spike/ckb-to-cardano/circuit/prover/target/release/advance_live
cd "$REL"
echo "-- full Groth16 prove on real header (st0 -> 21433591) --"
PROVE=1 CHIRAL_ADVANCE_STATE=/tmp/st0.json CHIRAL_ADVANCE_STEP=/tmp/step1.json "$BIN" > /tmp/live_redeemer.json 2>/tmp/live_prove.log
grep -E "arkworks verify|new_total" /tmp/live_prove.log
echo "-- cross-check: redeemer.new_state == relayer native apply (st1.json) --"
python3 - <<'PY'
import json
r = json.load(open("/tmp/live_redeemer.json"))["new_state"]
s = json.load(open("/tmp/st1.json"))
keys = ["chain_root", "total_difficulty", "window_root", "tip_height"]
ok = all(str(r[k]) == str(s[k]) for k in keys)
for k in keys:
    print(f"  {k}: snark={str(r[k])[:24]} relayer={str(s[k])[:24]} {'OK' if str(r[k])==str(s[k]) else 'MISMATCH'}")
print("CROSSCHECK", "MATCH" if ok else "MISMATCH")
PY
echo "AC2_PROVE_DONE"
