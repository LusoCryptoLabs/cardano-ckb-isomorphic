"""leap_to_ckb_ours.py <recipient_lock_hash_hex> - S5 LEAP_TO_CKB Cardano leg (CardanoBound -> CkbOwned).

The DANGEROUS direction: ownership returns to CKB and a permissionless relayer builds the CKB tx, so the
recipient must be bound owner-side. The owner SPENDS the seal at binding_lock with the LeapToCkb redeemer
(Constr 123 carrying the chosen 32-byte CKB recipient_lock_hash) and RE-PARKS the seal with a 3-field
LeapSealDatum { owner, commitment = RC, recipient_lock_hash }. binding_lock forces the continuing datum's
recipient to equal the owner-signed redeemer recipient (B1: no relayer substitution).

  RC = blake2b256( state ‖ SOURCE_seal(36 = s4_transfer_txid ‖ idx u32 LE) ‖ recipient_lock_hash(32) )

The CKB S5 branch (bound_asset_v2::leap_to_ckb) recomputes RC, pins the surviving CkbOwned cell's ACTUAL
lock to recipient (B3), and inserts the SOURCE seal nullifier (B4). SOURCE seal = the CardanoBound cell's
seal = the S4 transfer's re-parked seal outpoint. Keyless (Koios), native aiken, MANUAL ExUnits.
Records s5_leap_tx / s5_seal_index / s5_recipient / s5_rc to seal-instance-ours.json.
"""
import sys, os, json, subprocess, hashlib
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import cbor2, cardano_net
import pycardano as pc

ROOT = os.path.normpath(os.path.join(HERE, ".."))
INST = os.path.join(ROOT, "deployed", "cardano", "preview", "seal-instance-ours.json")
AIKEN = os.environ.get("AIKEN", os.path.join(os.path.expanduser("~"), ".aiken", "bin", "aiken"))
# default recipient = our Pudge relayer lock hash (so the CkbOwned cell returns to us)
DEFAULT_RECIPIENT = "7a971a3b730d3e5b69f73ac7add6dcd2396cab9523176132ed23e17500c820c7"

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
    recipient = bytes.fromhex(sys.argv[1]) if len(sys.argv) > 1 else bytes.fromhex(DEFAULT_RECIPIENT)
    if len(recipient) != 32: raise SystemExit("recipient_lock_hash must be 32 bytes (a CKB lock script hash)")
    inst = json.load(open(INST))
    SEALPOL = inst["seal_policy"]; SEAL_NAME = bytes.fromhex(inst["seal_name_hex"]); LADDR = inst["binding_lock_addr"]
    state = bytes.fromhex(inst.get("s4_state_hex", inst["S0_hex"]))                 # SAME state as the CardanoBound cell
    s4_txid = inst["s4_transfer_tx"]; s4_idx = int(inst["s4_seal_index"])           # SOURCE seal outpoint (CKB cell's seal)
    src_seal36 = bytes.fromhex(s4_txid) + s4_idx.to_bytes(4, "little")
    rc = hashlib.blake2b(state + src_seal36 + recipient, digest_size=32).digest()   # RC keystone (plain blake2b-256)

    ctx = cardano_net.chain_context(); sk, vk, addr = cardano_net.account("coordinator")
    owner = vk.hash().payload
    lock_script = lock_script_for(SEALPOL, SEAL_NAME)
    nft = pc.MultiAsset.from_primitive({bytes.fromhex(SEALPOL): {SEAL_NAME: 1}})
    seal = next(u for u in ctx.utxos(LADDR)
                if u.output.amount.multi_asset and pc.ScriptHash(bytes.fromhex(SEALPOL)) in u.output.amount.multi_asset.data)
    print("seal UTxO (SOURCE):", str(seal.input.transaction_id)[:16], "#", seal.input.index,
          "(expected", s4_txid[:16], "#", s4_idx, ")")

    leap_datum = pc.RawPlutusData(cbor2.CBORTag(121, [owner, rc, recipient]))        # 3-field LeapSealDatum
    leap_redeemer = pc.Redeemer(pc.RawPlutusData(cbor2.CBORTag(123, [recipient])),   # LeapToCkb{recipient} (Constr 2)
                                pc.ExecutionUnits(4_000_000, 1_600_000_000))
    collat = next(u for u in ctx.utxos(str(addr)) if not u.output.amount.multi_asset and int(u.output.amount.coin) >= 5_000_000)
    b = pc.TransactionBuilder(ctx)
    b.add_script_input(seal, script=lock_script, redeemer=leap_redeemer)
    b.add_input_address(addr)
    b.add_output(pc.TransactionOutput(pc.Address.from_primitive(LADDR), pc.Value(2_000_000, nft), datum=leap_datum))  # re-park (index 0)
    b.required_signers = [vk.hash()]
    b.collaterals = [collat]
    tx = b.build_and_sign([sk], change_address=addr)
    txid = str(tx.id)
    seal_index = next(i for i, o in enumerate(tx.transaction_body.outputs)
                      if o.amount.multi_asset and pc.ScriptHash(bytes.fromhex(SEALPOL)) in o.amount.multi_asset.data)
    ctx.submit_tx(tx)

    inst["s5_leap_tx"] = txid; inst["s5_seal_index"] = seal_index
    inst["s5_recipient"] = recipient.hex(); inst["s5_rc"] = rc.hex()
    json.dump(inst, open(INST, "w"), indent=2)
    print("\nS5 LEAP_TO_CKB (seal spent w/ LeapToCkb, RC datum re-parked) - preview tx:", txid)
    print("  recipient_lock_hash:", recipient.hex())
    print("  RC = blake2b256(state ‖ src_seal36 ‖ recipient) =", rc.hex())
    print("  seal re-parked at output index", seal_index)
    print("  CKB S5 builder: node leap_to_ckb_v2.mjs   (nullifier key = blake2b256(src_seal36))")

if __name__ == "__main__":
    main()
