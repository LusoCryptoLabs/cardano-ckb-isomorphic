#!/usr/bin/env python3
"""validate_window_binding.py - off-chain correctness gate for the ckbcert genesis Checkpoint datum.

The ckbcert genesis pins a Checkpoint{chain_root, total_difficulty, window_root(32B), tip_height}. The
leap_bound_windowed proof's public input #0 must equal cardano_bound.field_of(window_root) =
int.from_bytes(window_root, 'little') % fr_order. This recomputes the 32-byte window_root from the real
window leaves (the same ckbhash-merge the circuit uses) and checks it binds to the CEREMONY proof's PI[0],
AND that tip_height matches PI[3]. If this passes, the genesis Checkpoint datum is provably consistent with
the proof the relayer will submit - so the genesis mint will not brick the leg.
"""
import json, sys
from hashlib import blake2b

WINDOW = sys.argv[1] if len(sys.argv) > 1 else "/tmp/window.json"
REDEEMER = sys.argv[2] if len(sys.argv) > 2 else \
    "/mnt/c/Users/telmo/chiral-study/spike/ckb-to-cardano/circuit/ceremony/leap_bound_windowed_redeemer.json"
FR_ORDER = 52435875175126190479447740508185965837690552500527637822603658699938581184513

def ckbhash(b):
    h = blake2b(digest_size=32, person=b"ckb-default-hash"); h.update(b); return h.digest()

def window_root(leaves):
    level = [bytes.fromhex(x[2:] if x.startswith("0x") else x) for x in leaves]
    while len(level) > 1:
        level = [ckbhash(level[j] + level[j+1]) for j in range(0, len(level), 2)]
    return level[0]

w = json.load(open(WINDOW))
root = window_root(w["leaves"])
field = int.from_bytes(root, "little") % FR_ORDER
tip = w["tip_height"]

d = json.load(open(REDEEMER))
pi = [int(x) for x in d["public_inputs_dec"]]
pi0, pi3 = pi[0], pi[3]

print(f"window_root (32B hex)  = 0x{root.hex()}")
print(f"field_of(window_root)  = {field}")
print(f"proof PI[0]            = {pi0}")
print(f"tip_height (datum)     = {tip}   proof PI[3] = {pi3}")
ok_root = field == pi0
ok_tip = tip == pi3
print(f"BIND window_root->PI[0]: {'OK' if ok_root else 'MISMATCH'}")
print(f"BIND tip_height->PI[3] : {'OK' if ok_tip else 'MISMATCH'}")
if not (ok_root and ok_tip):
    sys.exit("BINDING FAILED - do NOT genesis the checkpoint with this datum")
print("OK: the genesis Checkpoint datum (window_root, tip_height) binds the ceremony proof.")
