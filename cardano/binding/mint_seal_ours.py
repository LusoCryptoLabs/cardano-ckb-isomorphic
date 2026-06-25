"""mint_seal_ours.py - mint a FRESH Chiral SEAL NFT at our binding_lock, under OUR funded preview key,
KEYLESS (Koios). Compiles+parameterizes seal_nft(seed) and binding_lock(seal_policy,name) with native
aiken, then builds the mint tx with MANUAL ExUnits (Koios has no tx-eval). Writes the live instance to
deployed/cardano/preview/seal-instance-ours.json. Plutus tx needs a separate collateral UTxO, so we
split first if the wallet has a single UTxO.
"""
import os, sys, json, subprocess, hashlib
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import cbor2
import pycardano as pc
import cardano_net

ROOT = os.path.normpath(os.path.join(HERE, ".."))
AIKEN = os.environ.get("AIKEN", os.path.join(os.path.expanduser("~"), ".aiken", "bin", "aiken"))
SEAL_NAME = b"SEAL"
S0 = b"bound-asset:demo:v1"            # initial CKB bound-cell state (genesis); commitment = blake2b256(S0)

def aiken(*args, cwd=HERE):
    r = subprocess.run([AIKEN, *args], cwd=cwd, capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"aiken {' '.join(args)} failed:\n{r.stdout}\n{r.stderr}")
    return r.stdout.strip()

def ensure_collateral(ctx, sk, addr):
    """Plutus tx needs a pure-ADA collateral UTxO distinct from the inputs. If we have <2 UTxOs, split."""
    us = ctx.utxos(str(addr))
    pure = [u for u in us if not u.output.amount.multi_asset]
    if len(pure) >= 2:
        return
    print("splitting wallet to create a dedicated collateral UTxO...")
    b = pc.TransactionBuilder(ctx)
    b.add_input_address(addr)
    b.add_output(pc.TransactionOutput(addr, pc.Value(5_000_000)))   # 5 tADA collateral
    b.add_output(pc.TransactionOutput(addr, pc.Value(5_000_000)))   # spare
    tx = b.build_and_sign([sk], change_address=addr)
    txid = ctx.submit_tx(tx)
    print("  split tx:", txid, "- waiting for confirmation...")
    wait_seen(ctx, addr, txid)

def wait_seen(ctx, addr, txid, tries=60):
    import time
    for _ in range(tries):
        for u in ctx.utxos(str(addr)):
            if str(u.input.transaction_id) == txid:
                return True
        time.sleep(10)
    raise TimeoutError(f"tx {txid} not seen after waiting")

def main():
    ctx = cardano_net.chain_context()
    sk, vk, addr = cardano_net.account("coordinator")
    owner = vk.hash().payload
    print("our address:", addr, "| owner vkh:", owner.hex())

    ensure_collateral(ctx, sk, addr)
    us = ctx.utxos(str(addr))
    pure = sorted([u for u in us if not u.output.amount.multi_asset], key=lambda u: int(u.output.amount.coin))
    collateral = pure[0]                       # smallest pure-ADA UTxO
    seed = pure[-1]                            # largest as seed+funding
    seed_txid = str(seed.input.transaction_id); seed_ix = seed.input.index
    print(f"seed {seed_txid[:16]}#{seed_ix} | collateral {str(collateral.input.transaction_id)[:16]}#{collateral.input.index}")

    # ---- parameterize the validators with native aiken (seed -> seal policy -> binding_lock) ----
    aiken("build")
    seed_cbor = cbor2.dumps(cbor2.CBORTag(121, [bytes.fromhex(seed_txid), seed_ix])).hex()
    name_cbor = cbor2.dumps(SEAL_NAME).hex()
    os.makedirs(os.path.join(HERE, "applied", "seal"), exist_ok=True)
    os.makedirs(os.path.join(HERE, "applied", "lock0"), exist_ok=True)
    os.makedirs(os.path.join(HERE, "applied", "lock"), exist_ok=True)
    for d in ("applied/seal", "applied/lock0", "applied/lock"):
        subprocess.run(["cp", "aiken.toml", d], cwd=HERE)
    aiken("blueprint", "apply", "-m", "seal_nft", "-v", "seal_nft", seed_cbor, "-o", "applied/seal/plutus.json")
    seal_pol = aiken("blueprint", "policy", "-m", "seal_nft", "-v", "seal_nft", cwd=os.path.join(HERE, "applied/seal"))
    aiken("blueprint", "apply", "-m", "binding_lock", "-v", "binding_lock", f"581c{seal_pol}", "-o", "applied/lock0/plutus.json")
    aiken("blueprint", "apply", "-m", "binding_lock", "-v", "binding_lock", name_cbor,
          "-i", "applied/lock0/plutus.json", "-o", "applied/lock/plutus.json")
    lock_addr = aiken("blueprint", "address", "-m", "binding_lock", "-v", "binding_lock", cwd=os.path.join(HERE, "applied/lock"))
    print("seal policy:", seal_pol, "\nbinding_lock:", lock_addr)

    bp = json.load(open(os.path.join(HERE, "applied/seal/plutus.json")))
    sv = next(v for v in bp["validators"] if v["title"] == "seal_nft.seal_nft.mint")
    seal_script = pc.PlutusV3Script(bytes.fromhex(sv["compiledCode"]))

    commitment = hashlib.blake2b(S0, digest_size=32).digest()
    seal_datum = pc.RawPlutusData(cbor2.CBORTag(121, [owner, commitment]))      # SealDatum{owner, commitment}
    nft = pc.MultiAsset.from_primitive({bytes.fromhex(seal_pol): {SEAL_NAME: 1}})
    lock = pc.Address.from_primitive(lock_addr)

    b = pc.TransactionBuilder(ctx)
    b.add_input(seed)
    b.add_input_address(addr)
    b.mint = nft
    b.add_minting_script(seal_script, pc.Redeemer(pc.RawPlutusData(cbor2.CBORTag(121, [])),
                                                   pc.ExecutionUnits(2_000_000, 700_000_000)))   # MANUAL ExUnits (no eval)
    b.add_output(pc.TransactionOutput(lock, pc.Value(2_000_000, nft), datum=seal_datum))
    b.required_signers = [vk.hash()]
    b.collaterals = [collateral]
    tx = b.build_and_sign([sk], change_address=addr)
    txid = ctx.submit_tx(tx)

    out = {"seal_policy": seal_pol, "seal_name_hex": SEAL_NAME.hex(), "binding_lock_addr": lock_addr,
           "owner_vkh": owner.hex(), "S0_hex": S0.hex(), "commitment": commitment.hex(),
           "seal_mint_tx": txid, "seed": f"{seed_txid}#{seed_ix}"}
    od = os.path.join(ROOT, "deployed", "cardano", "preview")
    os.makedirs(od, exist_ok=True)
    json.dump(out, open(os.path.join(od, "seal-instance-ours.json"), "w"), indent=2)
    print("\nFRESH SEAL MINTED - preview tx:", txid)
    print("  binding_lock:", lock_addr, "| commitment", commitment.hex()[:16], "= blake2b256(S0)")

if __name__ == "__main__":
    main()
