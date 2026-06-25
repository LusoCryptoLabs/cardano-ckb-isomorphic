"""deploy_seal.py - LIVE leap-in (preview): apply params + mint the SEAL NFT at binding_lock with
SealDatum{owner, commitment=blake2b256(S0)}. This creates a real bound-asset seal on Cardano."""
import sys, os, json, subprocess, hashlib
sys.path.insert(0, os.path.dirname(__file__))
import cbor2, cardano_net
import pycardano as pc

ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))
SEAL_NAME = b"SEAL"
S0 = b"bound-asset:demo:v1"                      # initial CKB bound-cell state (genesis)

def main():
    ctx = cardano_net.chain_context()
    sk, vk, addr = cardano_net.account("coordinator")
    owner = vk.hash().payload                     # 28-byte vkh = seal owner
    utxos = ctx.utxos(str(addr))
    seed = max(utxos, key=lambda u: int(u.output.amount.coin))
    seed_txid = str(seed.input.transaction_id); seed_ix = seed.input.index
    print(f"seed UTxO {seed_txid[:16]}…#{seed_ix}  owner {owner.hex()[:16]}…")

    seed_cbor = cbor2.dumps(cbor2.CBORTag(121, [bytes.fromhex(seed_txid), seed_ix])).hex()
    sh = '''export PATH=/aiken/bin:$PATH; set -e
aiken build >/dev/null 2>&1
ap() { mkdir -p $1; cp aiken.toml $1/; aiken blueprint apply -i ${5:-plutus.json} -m $2 -v $3 "$4" -o $1/plutus.json >/dev/null 2>&1; }
ap applied/seal seal_nft seal_nft "%s"
SEALPOL=$(cd applied/seal && aiken blueprint policy -m seal_nft -v seal_nft)
NAMECBOR=$(printf "%s")
ap applied/lock0 binding_lock binding_lock "581c${SEALPOL}"
ap applied/lock binding_lock binding_lock "${NAMECBOR}" applied/lock0/plutus.json
LADDR=$(cd applied/lock && aiken blueprint address -m binding_lock -v binding_lock)
echo "{\\"SEALPOL\\":\\"$SEALPOL\\",\\"LADDR\\":\\"$LADDR\\"}" > applied/seal_summary.json
''' % (seed_cbor, cbor2.dumps(SEAL_NAME).hex())
    subprocess.run([*cardano_net.AIKEN_DOCKER, sh], check=True, capture_output=True,
                   env={**os.environ, "MSYS_NO_PATHCONV": "1"})
    summ = json.load(open(os.path.join(ROOT, "applied", "seal_summary.json")))
    SEALPOL = summ["SEALPOL"]; LADDR = summ["LADDR"]
    bp = json.load(open(os.path.join(ROOT, "applied", "seal", "plutus.json")))
    sv = next(v for v in bp["validators"] if v["title"] == "seal_nft.seal_nft.mint")
    seal_script = pc.PlutusV3Script(bytes.fromhex(sv["compiledCode"]))
    print(f"seal policy {SEALPOL}\n binding_lock {LADDR}")

    commitment = hashlib.blake2b(S0, digest_size=32).digest()
    seal_datum = pc.RawPlutusData(cbor2.CBORTag(121, [owner, commitment]))   # SealDatum{owner, commitment}
    nft = pc.MultiAsset.from_primitive({bytes.fromhex(SEALPOL): {SEAL_NAME: 1}})
    lock_addr = pc.Address.from_primitive(LADDR)

    csk, _, caddr = cardano_net.account("collateral")
    collat = next(u for u in ctx.utxos(str(caddr)) if not u.output.amount.multi_asset)

    b = pc.TransactionBuilder(ctx)
    b.add_input(seed)
    b.add_input_address(addr)
    b.mint = nft
    b.add_minting_script(seal_script, pc.Redeemer(pc.RawPlutusData(cbor2.CBORTag(121, []))))
    b.add_output(pc.TransactionOutput(lock_addr, pc.Value(2_000_000, nft), datum=seal_datum))
    b.required_signers = [vk.hash()]
    b.collaterals = [collat]
    tx = b.build_and_sign([sk, csk], change_address=addr)
    txid = cardano_net.submit(tx, ctx)
    out = {"seal_policy": SEALPOL, "seal_name_hex": SEAL_NAME.hex(), "binding_lock_addr": LADDR,
           "owner_vkh": owner.hex(), "S0_hex": S0.hex(), "commitment": commitment.hex(),
           "seal_mint_tx": txid}
    os.makedirs(os.path.join(ROOT, "deployed", "cardano", "preview"), exist_ok=True)
    json.dump(out, open(os.path.join(ROOT, "deployed", "cardano", "preview", "seal-instance.json"), "w"), indent=2)
    print("\nLEAP-IN seal minted - preview tx:", txid)
    print("  bound-asset seal now lives at the binding_lock; commitment", commitment.hex()[:16], "= blake2b256(S0)")

if __name__ == "__main__":
    main()
