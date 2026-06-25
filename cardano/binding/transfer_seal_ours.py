"""transfer_seal_ours.py - TRANSFER our seal at the binding_lock (Transfer redeemer): spend the seal and
recreate it with a new SealDatum committing to S1. Drives the CKB TRANSITION. Keyless (Koios), native
aiken, MANUAL ExUnits (Koios has no tx-eval). Updates seal-instance-ours.json with transfer_tx + S1."""
import sys, os, json, subprocess, hashlib
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import cbor2, cardano_net
import pycardano as pc

ROOT = os.path.normpath(os.path.join(HERE, ".."))
INST = os.path.join(ROOT, "deployed", "cardano", "preview", "seal-instance-ours.json")
AIKEN = os.environ.get("AIKEN", os.path.join(os.path.expanduser("~"), ".aiken", "bin", "aiken"))
S1 = b"bound-asset:demo:v2 owner=bob"

def aiken(*a, cwd=HERE):
    r = subprocess.run([AIKEN, *a], cwd=cwd, capture_output=True, text=True)
    if r.returncode: raise RuntimeError(f"aiken {' '.join(a)}:\n{r.stdout}\n{r.stderr}")
    return r.stdout.strip()

def lock_script_for(seal_pol, seal_name):
    aiken("build")
    for d in ("applied/lock0", "applied/lock"):
        os.makedirs(os.path.join(HERE, d), exist_ok=True); subprocess.run(["cp", "aiken.toml", d], cwd=HERE)
    aiken("blueprint", "apply", "-m", "binding_lock", "-v", "binding_lock", cbor2.dumps(bytes.fromhex(seal_pol)).hex(),
          "-o", "applied/lock0/plutus.json")
    aiken("blueprint", "apply", "-m", "binding_lock", "-v", "binding_lock", cbor2.dumps(seal_name).hex(),
          "-i", "applied/lock0/plutus.json", "-o", "applied/lock/plutus.json")
    bp = json.load(open(os.path.join(HERE, "applied/lock/plutus.json")))
    lv = next(v for v in bp["validators"] if v["title"] == "binding_lock.binding_lock.spend")
    return pc.PlutusV3Script(bytes.fromhex(lv["compiledCode"]))

def main():
    inst = json.load(open(INST))
    SEALPOL = inst["seal_policy"]; SEAL_NAME = bytes.fromhex(inst["seal_name_hex"]); LADDR = inst["binding_lock_addr"]
    ctx = cardano_net.chain_context(); sk, vk, addr = cardano_net.account("coordinator")
    owner = vk.hash().payload
    lock_script = lock_script_for(SEALPOL, SEAL_NAME)
    nft = pc.MultiAsset.from_primitive({bytes.fromhex(SEALPOL): {SEAL_NAME: 1}})
    seal = next(u for u in ctx.utxos(LADDR)
                if u.output.amount.multi_asset and pc.ScriptHash(bytes.fromhex(SEALPOL)) in u.output.amount.multi_asset.data)
    print("seal UTxO:", str(seal.input.transaction_id)[:16], "#", seal.input.index)
    new_commitment = hashlib.blake2b(S1, digest_size=32).digest()
    new_datum = pc.RawPlutusData(cbor2.CBORTag(121, [owner, new_commitment]))
    transfer = pc.Redeemer(pc.RawPlutusData(cbor2.CBORTag(121, [])), pc.ExecutionUnits(3_000_000, 1_200_000_000))
    collat = next(u for u in ctx.utxos(str(addr)) if not u.output.amount.multi_asset and int(u.output.amount.coin) >= 5_000_000)
    b = pc.TransactionBuilder(ctx)
    b.add_script_input(seal, script=lock_script, redeemer=transfer)
    b.add_input_address(addr)
    b.add_output(pc.TransactionOutput(pc.Address.from_primitive(LADDR), pc.Value(2_000_000, nft), datum=new_datum))
    b.required_signers = [vk.hash()]
    b.collaterals = [collat]
    tx = b.build_and_sign([sk], change_address=addr)
    txid = ctx.submit_tx(tx)
    inst["transfer_tx"] = txid; inst["S1_hex"] = S1.hex(); inst["new_commitment"] = new_commitment.hex()
    json.dump(inst, open(INST, "w"), indent=2)
    print("\nTRANSFER (seal spent + recreated) - preview tx:", txid, "\n  new commitment", new_commitment.hex()[:16], "= blake2b256(S1)")

if __name__ == "__main__":
    main()
