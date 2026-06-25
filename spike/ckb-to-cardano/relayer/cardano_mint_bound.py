#!/usr/bin/env python3
"""Conservation-safe χCKB mint (Stage 0): mint via the AMOUNT-BINDING zk_chiral_mint policy, so the on-chain
validator enforces qty == the locked amount the relay_bind proof committed to (not the old proof-only mint).

Redeemer = MintRedeemer { proof, public_inputs, state, seal } where state = amount(16 LE) ‖ recipient(28)
(== relay_bind's in-circuit new_state). The applied policy bakes in the vk + ft_name, so an attacker can
neither swap the vk nor the name. Headless (server key) here only to validate ON-CHAIN ACCEPTANCE; the dApp
does the identical mint user-signed via Lucid.

  python3 cardano_mint_bound.py <leapproof.json> <applied_policy.json>
"""
import json
import os
import sys
import time
from dataclasses import dataclass
from typing import List
from pycardano import (BlockFrostChainContext, Network, Address, PaymentSigningKey, PaymentVerificationKey,
                       TransactionBuilder, TransactionOutput, Value, PlutusV3Script, plutus_script_hash,
                       PlutusData, Redeemer, MultiAsset, VerificationKeyHash)
from pycardano.serialization import ByteString

PROOF, APPLIED = sys.argv[1], sys.argv[2]
ctx = BlockFrostChainContext(__import__("os").environ.get("BLOCKFROST_PROJECT_ID",""), base_url="https://cardano-preview.blockfrost.io/api")
k = json.load(open(os.environ.get("CHIRAL_CARDANO_KEY", "/tmp/cardano_key.json")))
sk = PaymentSigningKey.from_primitive(bytes.fromhex(k["sk_hex"]))
addr = Address(payment_part=PaymentVerificationKey.from_signing_key(sk).hash(), network=Network.TESTNET)

fx = json.load(open(PROOF))
ap = json.load(open(APPLIED))
script = PlutusV3Script(bytes.fromhex(ap["compiledCode"]))
policy = plutus_script_hash(script)
assert policy.payload.hex() == ap["policy_id"], f"policy mismatch {policy.payload.hex()} != {ap['policy_id']}"
name = bytes.fromhex(ap["ft_name_hex"])


def B(h): return ByteString(bytes.fromhex(h.replace("0x", "")))


@dataclass
class ProofD(PlutusData):
    CONSTR_ID = 0
    a: ByteString; b: ByteString; c: ByteString


# state = amount(16 LE) ‖ recipient(28)  - the exact preimage relay_bind hashed for `commitment`.
amount = int(fx["amount"])
recipient = bytes.fromhex(fx["recipient"].replace("0x", ""))
seal = bytes.fromhex(fx["seal"].replace("0x", ""))
state = amount.to_bytes(16, "little") + recipient
assert len(state) == 44 and len(seal) == 32


@dataclass
class Mint(PlutusData):
    CONSTR_ID = 0
    proof: ProofD
    public_inputs: List[int]
    state: bytes
    seal: bytes


red = Mint(
    ProofD(B(fx["proof"]["a"]), B(fx["proof"]["b"]), B(fx["proof"]["c"])),
    [int(x) for x in fx["public_inputs_dec"]],
    state, seal,
)
mint = MultiAsset.from_primitive({policy.payload: {name: amount}})

b = TransactionBuilder(ctx)
b.add_input_address(addr)
b.mint = mint
b.add_minting_script(script, redeemer=Redeemer(red))
# the minted χCKB lands at the bound recipient (== our key's enterprise address)
rcpt = Address(payment_part=VerificationKeyHash(recipient), network=Network.TESTNET)
b.add_output(TransactionOutput(rcpt, Value(2_000_000, mint)))
try:
    signed = b.build_and_sign([sk], change_address=addr)
except Exception as e:
    # surface the full evaluation detail Blockfrost returns (empty ScriptFailures hides the reason)
    import json as _j
    def dump(o, d=0):
        if hasattr(o, "__dict__"): return {k: dump(v, d+1) for k, v in vars(o).items()}
        if isinstance(o, dict): return {k: dump(v, d+1) for k, v in o.items()}
        if isinstance(o, (list, tuple)): return [dump(x, d+1) for x in o]
        return str(o)
    print("EVAL FAILURE DETAIL:", _j.dumps(dump(e.args[0]) if e.args else str(e), indent=2)[:2000])
    raise SystemExit(1)
ctx.submit_tx(signed)
print("MINT_TXID", str(signed.id))
print("POLICY", policy.payload.hex(), "NAME", name.decode(errors="replace"), "QTY", amount)
json.dump({"mint_txid": str(signed.id), "policy_id": policy.payload.hex(), "asset_name_hex": name.hex(),
           "qty": amount, "amount_bound": amount}, open("/tmp/mint_bound.json", "w"))
