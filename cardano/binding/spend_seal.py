"""spend_seal.py - LIVE transfer (preview): spend the seal at binding_lock with the Transfer
redeemer, recreating the seal with a new SealDatum committing to S1. Exercises binding_lock live."""
import sys, os, json, subprocess, hashlib
sys.path.insert(0, os.path.dirname(__file__))
import cbor2, cardano_net
import pycardano as pc

ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))
S1 = b"bound-asset:demo:v2 owner=bob"   # the NEXT bound-cell state

def main():
    inst = json.load(open(os.path.join(ROOT, "deployed", "cardano", "preview", "seal-instance.json")))
    SEALPOL = inst["seal_policy"]; SEAL_NAME = bytes.fromhex(inst["seal_name_hex"]); LADDR = inst["binding_lock_addr"]
    ctx = cardano_net.chain_context()
    sk, vk, addr = cardano_net.account("coordinator")
    owner = vk.hash().payload

    # re-apply binding_lock(seal_policy, seal_name) to get its script
    pol_cbor = cbor2.dumps(bytes.fromhex(SEALPOL)).hex(); name_cbor = cbor2.dumps(SEAL_NAME).hex()
    sh = '''export PATH=/aiken/bin:$PATH; set -e
aiken build >/dev/null 2>&1
ap() { mkdir -p $1; cp aiken.toml $1/; aiken blueprint apply -i ${5:-plutus.json} -m $2 -v $3 "$4" -o $1/plutus.json >/dev/null 2>&1; }
ap applied/lock0 binding_lock binding_lock "%s"
ap applied/lock binding_lock binding_lock "%s" applied/lock0/plutus.json
''' % (pol_cbor, name_cbor)
    subprocess.run([*cardano_net.AIKEN_DOCKER, sh], check=True, capture_output=True,
                   env={**os.environ, "MSYS_NO_PATHCONV": "1"})
    bp = json.load(open(os.path.join(ROOT, "applied", "lock", "plutus.json")))
    lv = next(v for v in bp["validators"] if v["title"] == "binding_lock.binding_lock.spend")
    lock_script = pc.PlutusV3Script(bytes.fromhex(lv["compiledCode"]))

    # find the seal UTxO (carries the seal NFT) at the lock
    nft = pc.MultiAsset.from_primitive({bytes.fromhex(SEALPOL): {SEAL_NAME: 1}})
    seal_utxo = next(u for u in ctx.utxos(LADDR)
                     if u.output.amount.multi_asset and pc.ScriptHash(bytes.fromhex(SEALPOL)) in u.output.amount.multi_asset.data)
    print("seal UTxO:", str(seal_utxo.input.transaction_id)[:16], "#", seal_utxo.input.index)

    new_commitment = hashlib.blake2b(S1, digest_size=32).digest()
    new_datum = pc.RawPlutusData(cbor2.CBORTag(121, [owner, new_commitment]))   # SealDatum{owner, commitment(S1)}
    transfer = pc.Redeemer(pc.RawPlutusData(cbor2.CBORTag(121, [])))            # BindingRedeemer::Transfer

    csk, _, caddr = cardano_net.account("collateral")
    collat = next(u for u in ctx.utxos(str(caddr)) if not u.output.amount.multi_asset)

    b = pc.TransactionBuilder(ctx)
    b.add_script_input(seal_utxo, script=lock_script, redeemer=transfer)
    b.add_input_address(addr)
    b.add_output(pc.TransactionOutput(pc.Address.from_primitive(LADDR), pc.Value(2_000_000, nft), datum=new_datum))
    b.required_signers = [vk.hash()]
    b.collaterals = [collat]
    tx = b.build_and_sign([sk, csk], change_address=addr)
    txid = cardano_net.submit(tx, ctx)
    inst["transfer_tx"] = txid; inst["S1_hex"] = S1.hex(); inst["new_commitment"] = new_commitment.hex()
    json.dump(inst, open(os.path.join(ROOT, "deployed", "cardano", "preview", "seal-instance.json"), "w"), indent=2)
    print("\nTRANSFER (seal spent + recreated) - preview tx:", txid)
    print("  new commitment", new_commitment.hex()[:16], "= blake2b256(S1)")

if __name__ == "__main__":
    main()
