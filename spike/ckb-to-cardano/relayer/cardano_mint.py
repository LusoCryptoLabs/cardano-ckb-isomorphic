import json
from dataclasses import dataclass
from typing import List
from pycardano import (BlockFrostChainContext, Network, Address, PaymentSigningKey,
    PaymentVerificationKey, TransactionBuilder, TransactionOutput, Value, PlutusV3Script,
    plutus_script_hash, PlutusData, Redeemer, MultiAsset, ScriptHash)
from pycardano.serialization import ByteString
ctx=BlockFrostChainContext(__import__("os").environ.get("BLOCKFROST_PROJECT_ID",""), base_url="https://cardano-preview.blockfrost.io/api")
bp=json.load(open("groth16/plutus.json"))
v=[x for x in bp["validators"] if x["title"]=="zk_chiral_mint.zk_chiral_mint.mint"][0]
script=PlutusV3Script(bytes.fromhex(v["compiledCode"])); policy=plutus_script_hash(script)
k=json.load(open("/tmp/cardano_key.json")); sk=PaymentSigningKey.from_primitive(bytes.fromhex(k["sk_hex"]))
addr=Address(payment_part=PaymentVerificationKey.from_signing_key(sk).hash(), network=Network.TESTNET)
fx=json.load(open("circuit/prover/leap_proof.coherent.json"))
def B(h): return ByteString(bytes.fromhex(h))
@dataclass
class VK(PlutusData):
    CONSTR_ID=0
    alpha_g1: ByteString; beta_g2: ByteString; gamma_g2: ByteString; delta_g2: ByteString; ic: List[ByteString]
@dataclass
class ProofD(PlutusData):
    CONSTR_ID=0
    a: ByteString; b: ByteString; c: ByteString
@dataclass
class MintRedeemer(PlutusData):
    CONSTR_ID=0
    vk: VK; proof: ProofD; public_inputs: List[int]
vkj=fx["vk"]
red=MintRedeemer(
  VK(B(vkj["alpha_g1"]),B(vkj["beta_g2"]),B(vkj["gamma_g2"]),B(vkj["delta_g2"]),[B(x) for x in vkj["ic"]]),
  ProofD(B(fx["proof"]["a"]),B(fx["proof"]["b"]),B(fx["proof"]["c"])),
  [int(x) for x in fx["public_inputs_dec"]])
NAME=b"ckCKB"; QTY=100000   # mirrors the 100,000 CKB locked (amount-binding is a production step)
mint=MultiAsset.from_primitive({policy.payload:{NAME:QTY}})
b=TransactionBuilder(ctx); b.add_input_address(addr); b.mint=mint
b.add_minting_script(script, redeemer=Redeemer(red))
b.add_output(TransactionOutput(addr, Value(2_000_000, mint)))
signed=b.build_and_sign([sk], change_address=addr); ctx.submit_tx(signed)
print("MINT_TXID", str(signed.id)); print("POLICY", policy.payload.hex()); print("UNIT", policy.payload.hex()+NAME.hex())
json.dump({"mint_txid":str(signed.id),"policy_id":policy.payload.hex(),"asset_name_hex":NAME.hex(),"qty":QTY}, open("/tmp/mint_tx.json","w"))
