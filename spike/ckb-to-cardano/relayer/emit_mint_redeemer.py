#!/usr/bin/env python3
"""Emit the conservation-safe χCKB mint params - no key, no submit (self-custody).

Turns a value-bound relay_bind proof into exactly what the browser dApp needs so the USER signs the mint in
their own CIP-30 wallet (Lucid):

  - redeemer_cbor : MintRedeemer { proof, public_inputs, state, seal } as Plutus-Data CBOR hex, where
                    state = amount(16 LE) ‖ recipient(28) == relay_bind's in-circuit `new_state`.
  - mint_script_hex : the APPLIED zk_chiral_mint policy (vk + ft_name baked in) the dApp attaches.
  - policy_id / asset_name_hex / qty : the unit + amount; the amount-binding validator enforces qty == amount.

The applied policy (policy_id + compiledCode + ft_name_hex) comes from build_chiral_policy.py
(zk_chiral_mint.applied.json). Pure offline - no BlockFrost, no signing key.

  python3 emit_mint_redeemer.py --proof <relay_bind.json> --applied <zk_chiral_mint.applied.json>
"""
import argparse
import json
import sys
from dataclasses import dataclass
from typing import List
from pycardano import PlutusV3Script, plutus_script_hash, PlutusData
from pycardano.serialization import ByteString


def B(h: str) -> ByteString:
    return ByteString(bytes.fromhex(h.replace("0x", "")))


@dataclass
class ProofD(PlutusData):
    CONSTR_ID = 0
    a: ByteString
    b: ByteString
    c: ByteString


# the redeemer the deployed (amount-binding) zk_chiral_mint validator accepts; field order matches the Aiken
# type MintRedeemer { proof, public_inputs, state, seal }.
@dataclass
class MintRedeemer(PlutusData):
    CONSTR_ID = 0
    proof: ProofD
    public_inputs: List[int]
    state: bytes
    seal: bytes


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--proof", required=True, help="relay_bind output (proof + public_inputs_dec + amount/recipient/seal)")
    ap.add_argument("--applied", required=True, help="zk_chiral_mint.applied.json (policy_id, compiledCode, ft_name_hex)")
    ap.add_argument("--out", default=None, help="also write JSON here (still printed to stdout)")
    a = ap.parse_args()

    fx = json.load(open(a.proof))
    ap_pol = json.load(open(a.applied))

    script = PlutusV3Script(bytes.fromhex(ap_pol["compiledCode"]))
    policy = plutus_script_hash(script).payload.hex()
    if policy != ap_pol["policy_id"]:
        print(f"applied policy hash mismatch {policy} != {ap_pol['policy_id']}", file=sys.stderr)
        return 2

    amount = int(fx["amount"])
    recipient = bytes.fromhex(fx["recipient"].replace("0x", ""))
    seal = bytes.fromhex(fx["seal"].replace("0x", ""))
    state = amount.to_bytes(16, "little") + recipient        # == relay_bind new_state
    if len(state) != 44 or len(seal) != 32:
        print(f"bad state/seal length: state={len(state)} seal={len(seal)}", file=sys.stderr)
        return 2

    red = MintRedeemer(
        ProofD(B(fx["proof"]["a"]), B(fx["proof"]["b"]), B(fx["proof"]["c"])),
        [int(x) for x in fx["public_inputs_dec"]],
        state, seal,
    )
    name_hex = ap_pol["ft_name_hex"]
    out = {
        "redeemer_cbor": red.to_cbor_hex(),
        "mint_script_hex": ap_pol["compiledCode"],     # the APPLIED policy (vk + ft_name baked in)
        "policy_id": policy,
        "asset_name_hex": name_hex,
        "unit": policy + name_hex,
        "qty": amount,                                  # amount-binding: minted qty must equal this
        "amount": str(amount),
        "recipient": fx.get("recipient"),
        "seal": fx.get("seal"),
        "commitment": fx.get("commitment"),
    }
    text = json.dumps(out, indent=2)
    if a.out:
        open(a.out, "w").write(text)
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
