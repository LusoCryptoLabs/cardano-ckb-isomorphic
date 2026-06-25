#!/usr/bin/env python3
"""Reverse leg, Cardano half: BURN χCKB. The zk_chiral_mint policy allows any pure burn (is_pure_burn -> True),
so no proof is needed - a negative mint with a well-formed (dummy) MintRedeemer suffices. This is what the
burn-gated CKB lock later releases against (a Mithril cert of THIS burn). Headless here to validate on-chain;
the dApp does the identical burn user-signed via Lucid.

  python3 cardano_burn_bound.py <applied_policy.json> <qty>
"""
import json
import os
import sys
from dataclasses import dataclass
from typing import List
from pycardano import (BlockFrostChainContext, Network, Address, PaymentSigningKey, PaymentVerificationKey,
                       TransactionBuilder, TransactionOutput, Value, PlutusV3Script, plutus_script_hash,
                       PlutusData, Redeemer, MultiAsset, AssetName, ScriptHash, Asset)
from pycardano.serialization import ByteString

APPLIED, QTY = sys.argv[1], int(sys.argv[2])
ctx = BlockFrostChainContext(__import__("os").environ.get("BLOCKFROST_PROJECT_ID",""), base_url="https://cardano-preview.blockfrost.io/api")
k = json.load(open(os.environ.get("CHIRAL_CARDANO_KEY", "/tmp/cardano_key.json")))
sk = PaymentSigningKey.from_primitive(bytes.fromhex(k["sk_hex"]))
addr = Address(payment_part=PaymentVerificationKey.from_signing_key(sk).hash(), network=Network.TESTNET)

ap = json.load(open(APPLIED))
script = PlutusV3Script(bytes.fromhex(ap["compiledCode"]))
policy = plutus_script_hash(script)
name = bytes.fromhex(ap["ft_name_hex"])


@dataclass
class ProofD(PlutusData):
    CONSTR_ID = 0
    a: ByteString; b: ByteString; c: ByteString


@dataclass
class MintRedeemer(PlutusData):
    CONSTR_ID = 0
    proof: ProofD
    public_inputs: List[int]
    state: bytes
    seal: bytes


# dummy redeemer - is_pure_burn short-circuits to True before verify(), so the fields are unused (but the
# redeemer must still be a well-formed MintRedeemer so the script can destructure it).
dummy = MintRedeemer(ProofD(ByteString(b""), ByteString(b""), ByteString(b"")), [], b"", b"")
burn = MultiAsset({ScriptHash(policy.payload): Asset({AssetName(name): -QTY})})

b = TransactionBuilder(ctx)
b.add_input_address(addr)
b.mint = burn
b.add_minting_script(script, redeemer=Redeemer(dummy))
signed = b.build_and_sign([sk], change_address=addr)
ctx.submit_tx(signed)
print("BURN_TXID", str(signed.id))
print("POLICY", policy.payload.hex(), "NAME", name.decode(errors="replace"), "BURNED", QTY)
json.dump({"burn_txid": str(signed.id), "policy_id": policy.payload.hex(), "asset_name_hex": name.hex(),
           "burned": QTY}, open("/tmp/burn_bound.json", "w"))
