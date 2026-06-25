#!/usr/bin/env python3
"""Diagnostic: build the conservation-safe mint with DUMMY execution units (skip pycardano's auto-eval),
then POST the tx to Blockfrost's evaluator directly to read the RAW failure (pycardano swallows the detail).
"""
import json, sys, base64, urllib.request
from dataclasses import dataclass
from typing import List
import pycardano
from pycardano import (BlockFrostChainContext, Network, Address, PaymentSigningKey, PaymentVerificationKey,
                       TransactionBuilder, TransactionOutput, Value, PlutusV3Script, plutus_script_hash,
                       Redeemer, MultiAsset, VerificationKeyHash, ExecutionUnits)
from pycardano.serialization import ByteString

PROOF, APPLIED = sys.argv[1], sys.argv[2]
PID = __import__("os").environ.get("BLOCKFROST_PROJECT_ID","")
ctx = BlockFrostChainContext(PID, base_url="https://cardano-preview.blockfrost.io/api")
# patch the evaluator so build() does not call it (we want the raw tx, then we evaluate ourselves)
ctx.evaluate_tx_cbor = lambda cbor: {"mint:0": ExecutionUnits(2_000_000, 8_000_000_000)}

k = json.load(open("/tmp/cardano_key.json"))
sk = PaymentSigningKey.from_primitive(bytes.fromhex(k["sk_hex"]))
addr = Address(payment_part=PaymentVerificationKey.from_signing_key(sk).hash(), network=Network.TESTNET)
fx = json.load(open(PROOF)); ap = json.load(open(APPLIED))
script = PlutusV3Script(bytes.fromhex(ap["compiledCode"])); policy = plutus_script_hash(script)
name = bytes.fromhex(ap["ft_name_hex"])
def B(h): return ByteString(bytes.fromhex(h.replace("0x", "")))
@dataclass
class ProofD(pycardano.PlutusData):
    CONSTR_ID = 0
    a: ByteString; b: ByteString; c: ByteString
@dataclass
class Mint(pycardano.PlutusData):
    CONSTR_ID = 0
    proof: ProofD
    public_inputs: List[int]
    state: bytes
    seal: bytes
amount = int(fx["amount"]); recipient = bytes.fromhex(fx["recipient"].replace("0x", "")); seal = bytes.fromhex(fx["seal"].replace("0x", ""))
red = Mint(ProofD(B(fx["proof"]["a"]), B(fx["proof"]["b"]), B(fx["proof"]["c"])),
           [int(x) for x in fx["public_inputs_dec"]], amount.to_bytes(16, "little") + recipient, seal)
mint = MultiAsset.from_primitive({policy.payload: {name: amount}})
b = TransactionBuilder(ctx); b.add_input_address(addr); b.mint = mint
b.add_minting_script(script, redeemer=Redeemer(red, ExecutionUnits(2_000_000, 8_000_000_000)))
b.add_output(TransactionOutput(Address(payment_part=VerificationKeyHash(recipient), network=Network.TESTNET), Value(2_000_000, mint)))
signed = b.build_and_sign([sk], change_address=addr)
cbor = signed.to_cbor_hex()
print("built tx, cbor bytes:", len(cbor) // 2, "| ex units mem=2e6 steps=8e9 (under max 14e6/10e9)")
# SUBMIT - the node's rejection is authoritative and specific (ScriptWitnessNotValidating, ExUnitsTooBig, ...)
req = urllib.request.Request("https://cardano-preview.blockfrost.io/api/v0/tx/submit",
    data=bytes.fromhex(cbor), headers={"project_id": PID, "Content-Type": "application/cbor"})
try:
    print("SUBMIT OK txid:", json.load(urllib.request.urlopen(req, timeout=30)))
except urllib.error.HTTPError as e:
    print("SUBMIT HTTP", e.code, ":", e.read().decode()[:2500])
