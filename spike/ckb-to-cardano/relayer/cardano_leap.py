import json, sys, time
from dataclasses import dataclass
from typing import List
from pycardano import (BlockFrostChainContext, Network, Address, PaymentSigningKey,
    PaymentVerificationKey, TransactionBuilder, TransactionOutput, Value, PlutusV3Script,
    plutus_script_hash, PlutusData, Redeemer)
from pycardano.serialization import ByteString
FX=sys.argv[1]
ctx=BlockFrostChainContext(__import__("os").environ.get("BLOCKFROST_PROJECT_ID",""), base_url="https://cardano-preview.blockfrost.io/api")
bp=json.load(open("/home/user/cardano-ckb-isomorphic/spike/ckb-to-cardano/groth16/plutus.json"))
v=[x for x in bp["validators"] if x["title"]=="zk_leap_lock.zk_leap_lock.spend"][0]
script=PlutusV3Script(bytes.fromhex(v["compiledCode"]))
script_addr=Address(payment_part=plutus_script_hash(script), network=Network.TESTNET)
k=json.load(open("/tmp/cardano_key.json")); sk=PaymentSigningKey.from_primitive(bytes.fromhex(k["sk_hex"]))
addr=Address(payment_part=PaymentVerificationKey.from_signing_key(sk).hash(), network=Network.TESTNET)
fx=json.load(open(FX))
def B(h): return ByteString(bytes.fromhex(h))
@dataclass
class VK(PlutusData):
    CONSTR_ID=0
    alpha_g1: ByteString; beta_g2: ByteString; gamma_g2: ByteString; delta_g2: ByteString; ic: List[ByteString]
@dataclass
class LockDatum(PlutusData):
    CONSTR_ID=0
    vk: VK; public_inputs: List[int]
@dataclass
class ProofD(PlutusData):
    CONSTR_ID=0
    a: ByteString; b: ByteString; c: ByteString
vkj=fx["vk"]
vk_d=VK(B(vkj["alpha_g1"]),B(vkj["beta_g2"]),B(vkj["gamma_g2"]),B(vkj["delta_g2"]),[B(x) for x in vkj["ic"]])
datum=LockDatum(vk_d,[int(x) for x in fx["public_inputs_dec"]])
proof=ProofD(B(fx["proof"]["a"]),B(fx["proof"]["b"]),B(fx["proof"]["c"]))
# LOCK
b=TransactionBuilder(ctx); b.add_input_address(addr)
b.add_output(TransactionOutput(script_addr, Value(5_000_000), datum=datum))
locked=b.build_and_sign([sk], change_address=addr); ctx.submit_tx(locked)
print("LOCK_TXID", str(locked.id), flush=True)
# wait for the script utxo
for _ in range(60):
    try:
        u=[x for x in ctx.utxos(script_addr) if str(x.input.transaction_id)==str(locked.id) and x.input.index==0]
        if u: break
    except Exception: pass
    time.sleep(10)
sutxo=u[0]
# SPEND (runs verify on-chain)
b=TransactionBuilder(ctx)
b.add_script_input(sutxo, script=script, redeemer=Redeemer(proof))
b.add_input_address(addr); b.add_output(TransactionOutput(addr, Value(2_000_000)))
spent=b.build_and_sign([sk], change_address=addr); ctx.submit_tx(spent)
print("SPEND_TXID", str(spent.id), flush=True)
json.dump({"lock_txid":str(locked.id),"spend_txid":str(spent.id),"target_block":fx["target_block"]}, open("/tmp/cardano_leap.json","w"))
