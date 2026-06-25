"""leap_to_cardano_ours.py - S4 LEAP_TO_CARDANO Cardano leg (CkbOwned -> CardanoBound).

The owner leaves CKB: ownership of the single living seal moves Cardano-side. Physically this is a
Transfer of the seal at binding_lock that RE-PARKS it with a 2-field SealDatum whose commitment =
blake2b256(state) for the SAME state the CkbOwned cell carries (state is UNCHANGED across S4). The
CKB S4 branch (bound_asset_v2::leap_to_cardano) then names THIS certified tx as the CardanoBound seal,
checks seal_at_lock==true + the state-only commitment, and zeroes the CardanoBound lock slot.

We reuse the genesis seal (same seal_policy baked into bound_asset_v2 args) instead of minting a new
one-shot policy - a fresh seal_nft(seed) would carry a DIFFERENT policy id and fail the verifier's
seal_at_lock(seal_policy) check. RGB++-style: one seal, ownership toggles by datum shape.

Keyless (Koios), native aiken, MANUAL ExUnits. Records s4_transfer_tx / s4_seal_index / s4_state to
seal-instance-ours.json for the CKB S4 builder + the S5 leg.
"""
import sys, os, json, subprocess, hashlib
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import cbor2, cardano_net
import pycardano as pc

ROOT = os.path.normpath(os.path.join(HERE, ".."))
INST = os.path.join(ROOT, "deployed", "cardano", "preview", "seal-instance-ours.json")
AIKEN = os.environ.get("AIKEN", os.path.join(os.path.expanduser("~"), ".aiken", "bin", "aiken"))

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
    # state is UNCHANGED across S4 (CardanoBound preserves the CkbOwned cell's state). Default = genesis S0.
    state = bytes.fromhex(inst["S0_hex"])
    ctx = cardano_net.chain_context(); sk, vk, addr = cardano_net.account("coordinator")
    owner = vk.hash().payload
    lock_script = lock_script_for(SEALPOL, SEAL_NAME)
    nft = pc.MultiAsset.from_primitive({bytes.fromhex(SEALPOL): {SEAL_NAME: 1}})
    seal = next(u for u in ctx.utxos(LADDR)
                if u.output.amount.multi_asset and pc.ScriptHash(bytes.fromhex(SEALPOL)) in u.output.amount.multi_asset.data)
    print("seal UTxO:", str(seal.input.transaction_id)[:16], "#", seal.input.index)

    commitment = hashlib.blake2b(state, digest_size=32).digest()      # state-only (live parity); state UNCHANGED
    new_datum = pc.RawPlutusData(cbor2.CBORTag(121, [owner, commitment]))   # 2-field SealDatum
    transfer = pc.Redeemer(pc.RawPlutusData(cbor2.CBORTag(121, [])), pc.ExecutionUnits(3_000_000, 1_200_000_000))  # Transfer
    collat = next(u for u in ctx.utxos(str(addr)) if not u.output.amount.multi_asset and int(u.output.amount.coin) >= 5_000_000)
    b = pc.TransactionBuilder(ctx)
    b.add_script_input(seal, script=lock_script, redeemer=transfer)
    b.add_input_address(addr)
    b.add_output(pc.TransactionOutput(pc.Address.from_primitive(LADDR), pc.Value(2_000_000, nft), datum=new_datum))  # re-park (index 0)
    b.required_signers = [vk.hash()]
    b.collaterals = [collat]
    tx = b.build_and_sign([sk], change_address=addr)
    txid = str(tx.id)
    # find the index of the re-parked seal output (the one carrying the seal NFT)
    seal_index = next(i for i, o in enumerate(tx.transaction_body.outputs)
                      if o.amount.multi_asset and pc.ScriptHash(bytes.fromhex(SEALPOL)) in o.amount.multi_asset.data)
    ctx.submit_tx(tx)

    inst["s4_transfer_tx"] = txid; inst["s4_seal_index"] = seal_index; inst["s4_state_hex"] = state.hex()
    inst["s4_commitment"] = commitment.hex()
    json.dump(inst, open(INST, "w"), indent=2)
    print("\nS4 LEAP_TO_CARDANO (seal transferred, state-only datum) - preview tx:", txid)
    print("  seal re-parked at output index", seal_index, "| state-only commitment", commitment.hex()[:16], "= blake2b256(state)")
    print("  CardanoBound seal for CKB S4 = (", txid, ",", seal_index, ")")

if __name__ == "__main__":
    main()
