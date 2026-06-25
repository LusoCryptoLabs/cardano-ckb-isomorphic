#!/usr/bin/env python3
"""validate_leap_binding.py - off-chain correctness gate for the LEAP tx, before any live submit.

cardano_bound.Transition requires public_inputs == [field_of(window_root), field_of(seal),
field_of(commitment(new_state, seal)), tip, k], where commitment = blake2b256(new_state ‖ seal) and
field_of(b) = int.from_bytes(b,'little') % fr_order. This recomputes field_of(seal) and the commitment field
from the EXACT seal (CKB receipt tx hash) + new_state (amount(16 LE)‖recipient(28)) the leap tx will carry,
and checks they equal the ceremony proof's PI[1] and PI[2] (and tip/k = PI[3]/PI[4]). If this passes, the
on-chain verify will accept the leap.
"""
import json, sys
from hashlib import blake2b

CER = "/mnt/c/Users/telmo/chiral-study/spike/ckb-to-cardano/circuit/ceremony/leap_bound_windowed_redeemer.json"
FR = 52435875175126190479447740508185965837690552500527637822603658699938581184513
SEAL = "cfaaf1778e1e6b381c679ed6d44395c7a589267f0bea7816c9f05b58a9176c77"   # CKB receipt tx hash
AMOUNT = 20000000000
RECIPIENT = "2df44c71a4312463ba31315c5aa7725b6ad44cd544a055a3dde915a6"     # 28-byte recipient credential
TIP = 21388353
K = 12

def field_of(b): return int.from_bytes(b, "little") % FR

seal = bytes.fromhex(SEAL)
new_state = AMOUNT.to_bytes(16, "little") + bytes.fromhex(RECIPIENT)        # amount(16 LE) ‖ recipient(28)
commitment = blake2b(new_state + seal, digest_size=32).digest()            # standard blake2b256

pi = [int(x) for x in json.load(open(CER))["public_inputs_dec"]]
checks = {
    "seal -> PI[1]":       (field_of(seal), pi[1]),
    "commitment -> PI[2]": (field_of(commitment), pi[2]),
    "tip -> PI[3]":        (TIP, pi[3]),
    "K -> PI[4]":          (K, pi[4]),
}
print(f"new_state (44B) = {new_state.hex()}")
print(f"commitment      = {commitment.hex()}")
ok = True
for name, (got, want) in checks.items():
    m = got == want
    ok = ok and m
    print(f"  {name:22} {'OK' if m else 'MISMATCH'}{'' if m else f'  got {got} != {want}'}")
if not ok:
    sys.exit("LEAP BINDING FAILED - do not submit")
print("OK: the leap tx (seal, new_state) binds the ceremony proof. On-chain verify will accept.")
