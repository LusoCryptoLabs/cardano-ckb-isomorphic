"""unbind_seal_ours.py - UNBIND our seal at the binding_lock (Unbind redeemer): spend the seal and
release the NFT to a PLAIN address (NOT recreated at the lock). Drives the CKB FINALIZE (leap-out).
Keyless (Koios), native aiken, MANUAL ExUnits. Updates seal-instance-ours.json with unbind_tx."""
import sys, os, json
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import cbor2, cardano_net
import pycardano as pc
from transfer_seal_ours import lock_script_for  # reuse the native-aiken param-apply

ROOT = os.path.normpath(os.path.join(HERE, ".."))
INST = os.path.join(ROOT, "deployed", "cardano", "preview", "seal-instance-ours.json")

def main():
    inst = json.load(open(INST))
    SEALPOL = inst["seal_policy"]; SEAL_NAME = bytes.fromhex(inst["seal_name_hex"]); LADDR = inst["binding_lock_addr"]
    ctx = cardano_net.chain_context(); sk, vk, addr = cardano_net.account("coordinator")
    lock_script = lock_script_for(SEALPOL, SEAL_NAME)
    nft = pc.MultiAsset.from_primitive({bytes.fromhex(SEALPOL): {SEAL_NAME: 1}})
    seal = next(u for u in ctx.utxos(LADDR)
                if u.output.amount.multi_asset and pc.ScriptHash(bytes.fromhex(SEALPOL)) in u.output.amount.multi_asset.data)
    print("seal UTxO:", str(seal.input.transaction_id)[:16], "#", seal.input.index)
    unbind = pc.Redeemer(pc.RawPlutusData(cbor2.CBORTag(122, [])), pc.ExecutionUnits(3_000_000, 1_200_000_000))  # Unbind variant
    collat = next(u for u in ctx.utxos(str(addr)) if not u.output.amount.multi_asset and int(u.output.amount.coin) >= 5_000_000)
    b = pc.TransactionBuilder(ctx)
    b.add_script_input(seal, script=lock_script, redeemer=unbind)
    b.add_input_address(addr)
    b.add_output(pc.TransactionOutput(addr, pc.Value(2_000_000, nft)))   # seal released to a PLAIN owner addr (not the lock)
    b.required_signers = [vk.hash()]
    b.collaterals = [collat]
    tx = b.build_and_sign([sk], change_address=addr)
    txid = ctx.submit_tx(tx)
    inst["unbind_tx"] = txid; json.dump(inst, open(INST, "w"), indent=2)
    print("\nLEAP-OUT (Unbind) - preview tx:", txid, "\n  seal released to a plain UTxO; asset unbound from the lock")

if __name__ == "__main__":
    main()
