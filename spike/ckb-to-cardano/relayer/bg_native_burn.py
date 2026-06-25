# Burn-gated demo: mint a trivial native-script token, then BURN it. The burn tx (mint field negative qty)
# is what Mithril certifies and burn_gated_unlock_v2 proves. Policy logic is irrelevant to burn_gated.
import json, time, sys, urllib.request
from pycardano import (BlockFrostChainContext, Network, Address, PaymentSigningKey, PaymentVerificationKey,
    TransactionBuilder, TransactionOutput, Value, MultiAsset, ScriptPubkey, ScriptAll)
BF=__import__("os").environ.get("BLOCKFROST_PROJECT_ID","")
ctx=BlockFrostChainContext(BF, base_url="https://cardano-preview.blockfrost.io/api")
k=json.load(open("/tmp/cardano_key.json")); sk=PaymentSigningKey.from_primitive(bytes.fromhex(k["sk_hex"]))
vk=PaymentVerificationKey.from_signing_key(sk); addr=Address(payment_part=vk.hash(), network=Network.TESTNET)
policy_script=ScriptAll([ScriptPubkey(vk.hash())]); POLICY=policy_script.hash()
NAME=b"chiCKB"; QTY=200
unit=POLICY.payload.hex()+NAME.hex()
print("address:", str(addr), "| policy:", POLICY.payload.hex(), "| name_hex:", NAME.hex(), "| qty:", QTY)

def confirmed(txid):
    try:
        urllib.request.urlopen(urllib.request.Request(
            "https://cardano-preview.blockfrost.io/api/v0/txs/"+txid, headers={"project_id":BF}), timeout=20); return True
    except urllib.error.HTTPError: return False

if sys.argv[1:] and sys.argv[1]=="mint":
    b=TransactionBuilder(ctx); b.add_input_address(addr)
    b.native_scripts=[policy_script]; b.mint=MultiAsset.from_primitive({POLICY.payload:{NAME:QTY}})
    b.add_output(TransactionOutput(addr, Value(2_000_000, MultiAsset.from_primitive({POLICY.payload:{NAME:QTY}}))))
    s=b.build_and_sign([sk], change_address=addr); ctx.submit_tx(s)
    print("MINT_TXID", str(s.id)); json.dump({"mint_txid":str(s.id),"policy":POLICY.payload.hex(),"name_hex":NAME.hex(),"qty":QTY}, open("/tmp/bg_mint.json","w"))
elif sys.argv[1:] and sys.argv[1]=="burn":
    tok=[u for u in ctx.utxos(addr) if u.output.amount.multi_asset and POLICY in u.output.amount.multi_asset]
    print("token utxos:", len(tok))
    if not tok: raise SystemExit("no token utxo to burn (run mint first + wait for confirmation)")
    b=TransactionBuilder(ctx)
    for u in tok: b.add_input(u)
    b.add_input_address(addr); b.native_scripts=[policy_script]; b.mint=MultiAsset.from_primitive({POLICY.payload:{NAME:-QTY}})
    s=b.build_and_sign([sk], change_address=addr); ctx.submit_tx(s)
    print("BURN_TXID", str(s.id)); print("UNIT", unit)
    json.dump({"burn_txid":str(s.id),"policy":POLICY.payload.hex(),"name_hex":NAME.hex(),"qty":QTY,"unit":unit}, open("/tmp/bg_burn.json","w"))
else:
    print("usage: bg_native_burn.py [mint|burn]")
