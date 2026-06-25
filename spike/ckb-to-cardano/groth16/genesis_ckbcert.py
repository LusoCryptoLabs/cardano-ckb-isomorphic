#!/usr/bin/env python3
"""genesis_ckbcert.py - LIVE genesis of the CKB-light-client checkpoint on Cardano preview (Groth16 leg).

Mints the one-shot ckbcert_thread NFT (consuming a wallet outpoint) onto a checkpoint cell at the
advance_ckbcert address, carrying the PINNED Checkpoint datum {chain_root, total_difficulty, window_root,
tip_height}. The window_root/tip are the REAL CKB window state the leap proof binds. chain_root == the anchor
tip's CKB block hash (header-chain follower, advance_live.rs), total_difficulty anchored at 0; AdvanceCKBCert is
baked with the ADVANCE ceremony vk so the checkpoint is ADVANCEABLE (advance_relayer.py drives it). Manual
ExUnits (Koios has no tx-eval), generous-but-safe.

  python3 genesis_ckbcert.py            # dry: parameterize + print the would-be tx (no submit)
  python3 genesis_ckbcert.py --live     # build + sign + submit, then verify on Koios
"""
import os, sys, json, subprocess
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, "..", "..", ".."))           # chiral-study
sys.path.insert(0, HERE)                                                # d6_deploy
sys.path.insert(0, os.path.join(ROOT, "cardano", "binding"))           # cardano_net
import cbor2
import pycardano as pc
import cardano_net
import d6_deploy as d6

CER = os.path.join(HERE, "..", "circuit", "ceremony")
# AdvanceCKBCert is parameterized with the ADVANCE circuit vk (advance_live, header-chain follower: 7 public
# inputs / ic len 8), NOT the leap vk -- the validator binds a 7-input advance proof, so the leap vk (5 inputs)
# could never verify one. Use the CEREMONY vk (toxic waste destroyed; a seeded vk would let anyone forge advances).
VK = json.load(open(os.path.join(CER, "advance_live_ceremony_redeemer.json")))["vk"]
WINDOW_ROOT = os.environ.get("CHIRAL_WINDOW_ROOT", "6f01df31e1fe4b799e95d7e59f5ae8ce57f3cf94945bcf5f76c67da050cf2f85")
TIP_HEIGHT  = int(os.environ.get("CHIRAL_TIP_HEIGHT", "21388353"))
# header-chain follower: chain_root == the anchor tip's CKB block hash (NOT zero); total_difficulty anchored at 0
# (cumulative work is summed from here by each advance). Set CHIRAL_CHAIN_ROOT from `advance_relayer.py init`.
CHAIN_ROOT = os.environ.get("CHIRAL_CHAIN_ROOT", "00" * 32)
TOTAL_DIFF = "00" * 32
THREAD_NAME = bytes.fromhex("636b62636572742d746872656164")             # "ckbcert-thread"
OUT_ADA = 5_000_000
EXU = pc.ExecutionUnits(6_000_000, 2_000_000_000)                       # generous; well under per-tx limits

def compiled(label, n, name):
    # the applied plutus.json holds ALL validators; pick THIS one by name (else the first .mint is a
    # different validator whose hash won't match the derived policy id).
    bp = json.load(open(f"{d6.WORK}/{label}_{n}.json"))
    v = next(x for x in bp["validators"]
             if x["title"].startswith(name + ".") and (x["title"].endswith(".mint") or x["title"].endswith(".spend")))
    return bytes.fromhex(v["compiledCode"])

def main():
    live = "--live" in sys.argv
    # header-chain follower: a real anchor tip hash is MANDATORY for --live (a silent 00*32 chain_root would
    # pin an un-anchored lineage forever). Dry runs may keep the placeholder.
    if live and "CHIRAL_CHAIN_ROOT" not in os.environ:
        sys.exit("set CHIRAL_CHAIN_ROOT to the anchor tip CKB block hash (advance_relayer.py init -> state.chain_root) before --live")
    assert len(bytes.fromhex(CHAIN_ROOT)) == 32 and len(bytes.fromhex(WINDOW_ROOT)) == 32, "CHAIN_ROOT/WINDOW_ROOT must be 32 bytes"
    ctx = cardano_net.chain_context()
    sk, vk, addr = cardano_net.account()
    print("address:", addr)

    us = ctx.utxos(str(addr))
    pure = sorted([u for u in us if not u.output.amount.multi_asset], key=lambda u: int(u.output.amount.coin))
    if len(pure) < 2:
        sys.exit("need >=2 pure-ADA UTxOs (a gref+funding and a collateral); split the wallet first")
    seed = pure[-1]                                   # largest pure UTxO funds the mint + change
    # collateral must cover the min collateral (~3.82 ADA); the smallest pure UTxO can be too tiny (leftover
    # change), so pick the smallest pure UTxO that is >= 5 ADA and is NOT the seed.
    collateral = next((u for u in pure if int(u.output.amount.coin) >= 5_000_000 and u.input != seed.input), None)
    if collateral is None:
        sys.exit("need a pure-ADA UTxO >= 5 ADA (distinct from the seed) for collateral; consolidate the wallet")
    gref_txid = str(seed.input.transaction_id); gref_ix = seed.input.index
    print(f"gref {gref_txid[:16]}#{gref_ix}  collateral {str(collateral.input.transaction_id)[:16]}#{collateral.input.index}  seed {int(seed.output.amount.coin)/1e6:.1f} tADA")

    subprocess.run([d6.AIKEN, "build"], cwd=HERE, check=True, capture_output=True)
    # advance_ckbcert(vk) -> cp_script (the address the checkpoint cell sits at)
    cp_script = d6.apply_chain("advance_ckbcert", "advance_ckbcert", [d6.C_vk(VK)], "adv")
    # pinned Checkpoint datum (param AND the output datum - must be byte-identical)
    pinned_struct = d6.constr(0, [bytes.fromhex(CHAIN_ROOT), bytes.fromhex(TOTAL_DIFF), bytes.fromhex(WINDOW_ROOT), TIP_HEIGHT])
    pinned_param = cbor2.dumps(pinned_struct).hex()
    # ckbcert_thread(gref, pinned, cp_script) -> CHECKPOINT_NFT policy id + the compiled minting script
    policy_id = d6.apply_chain("ckbcert_thread", "ckbcert_thread",
                               [d6.C_oref(gref_txid, gref_ix), pinned_param, d6.C_bytes(cp_script)], "ckbc")
    thread_script = pc.PlutusV3Script(compiled("ckbc", 3, "ckbcert_thread"))
    assert pc.script_hash(thread_script).payload.hex() == policy_id, "script hash != derived policy id"

    adv_addr = pc.Address(payment_part=pc.ScriptHash(bytes.fromhex(cp_script)), network=pc.Network.TESTNET)
    nft = pc.MultiAsset.from_primitive({bytes.fromhex(policy_id): {THREAD_NAME: 1}})
    checkpoint_datum = pc.RawPlutusData(pinned_struct)
    print("cp_script (advance addr):", cp_script)
    print("CHECKPOINT_NFT:", policy_id)
    print("pinned: window_root", WINDOW_ROOT[:16], "tip", TIP_HEIGHT)

    if not live:
        print("\n[dry] would mint 1 ckbcert-thread NFT -> checkpoint cell at advance addr (re-run with --live)")
        return

    b = pc.TransactionBuilder(ctx)
    b.add_input(seed)
    b.add_input_address(addr)
    b.mint = nft
    b.add_minting_script(thread_script, pc.Redeemer(pc.RawPlutusData(cbor2.CBORTag(121, [])), EXU))
    b.add_output(pc.TransactionOutput(adv_addr, pc.Value(OUT_ADA, nft), datum=checkpoint_datum))
    b.collaterals = [collateral]
    tx = b.build_and_sign([sk], change_address=addr)
    txid = ctx.submit_tx(tx)
    print("\nLIVE ckbcert genesis submitted - preview tx:", txid)

    od = os.path.join(ROOT, "deployed", "cardano", "preview")
    os.makedirs(od, exist_ok=True)
    out = {"checkpoint_nft": policy_id, "advance_ckbcert_script": cp_script, "advance_addr": str(adv_addr),
           "genesis_tx": txid, "gref": f"{gref_txid}#{gref_ix}", "thread_name_hex": THREAD_NAME.hex(),
           "pinned": {"chain_root": CHAIN_ROOT, "total_difficulty": TOTAL_DIFF, "window_root": WINDOW_ROOT, "tip_height": TIP_HEIGHT}}
    json.dump(out, open(os.path.join(od, "ckbcert-genesis.json"), "w"), indent=2)
    print("  state -> deployed/cardano/preview/ckbcert-genesis.json")

if __name__ == "__main__":
    main()
