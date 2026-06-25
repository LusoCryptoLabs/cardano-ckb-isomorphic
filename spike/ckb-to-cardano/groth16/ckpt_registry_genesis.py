#!/usr/bin/env python3
"""ckpt_registry_genesis.py - E2: ONE-TIME genesis of the STABLE checkpoint-registry cell for the χADA return.

Mints the one-shot ckbcert_thread NFT (REUSED - same minting policy as the advance checkpoint, but pinned to
the ckpt_registry script hash so it is a DISTINCT lineage) onto a checkpoint cell at the ckpt_registry address,
carrying the PINNED Checkpoint datum {chain_root, total_difficulty, window_root, tip_height}. Thereafter the
GOVERNOR re-anchors this cell IN PLACE (ckpt_reanchor.py), preserving the NFT - so its NFT, and the ada_escrow
that bakes it, stay STABLE across every return (no per-return re-genesis / ref-script churn).

The governor is the relayer's own Cardano payment key hash (the same authority that runs genesis_ckbcert today).

  python3 ckpt_registry_genesis.py            # dry: parameterize + print the would-be tx (no submit)
  CHIRAL_CHAIN_ROOT=.. CHIRAL_WINDOW_ROOT=.. CHIRAL_TIP_HEIGHT=.. python3 ckpt_registry_genesis.py --live
"""
import os, sys, json, subprocess
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, "..", "..", ".."))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(ROOT, "cardano", "binding"))
import cbor2
import pycardano as pc
import cardano_net
import d6_deploy as d6

# the INITIAL anchor (the current return checkpoint's window/tip). A real anchor tip hash is MANDATORY for
# --live (a silent 00*32 chain_root would pin an un-anchored lineage). Set from advance_relayer.py init.
WINDOW_ROOT = os.environ.get("CHIRAL_WINDOW_ROOT", "6f01df31e1fe4b799e95d7e59f5ae8ce57f3cf94945bcf5f76c67da050cf2f85")
TIP_HEIGHT  = int(os.environ.get("CHIRAL_TIP_HEIGHT", "21388353"))
CHAIN_ROOT  = os.environ.get("CHIRAL_CHAIN_ROOT", "00" * 32)
TOTAL_DIFF  = os.environ.get("CHIRAL_TOTAL_DIFF", "00" * 32)
THREAD_NAME = bytes.fromhex("636b62636572742d746872656164")             # "ckbcert-thread"
OUT_ADA = 5_000_000
EXU = pc.ExecutionUnits(6_000_000, 2_000_000_000)

def compiled(label, n, name):
    bp = json.load(open(f"{d6.WORK}/{label}_{n}.json"))
    v = next(x for x in bp["validators"]
             if x["title"].startswith(name + ".") and (x["title"].endswith(".mint") or x["title"].endswith(".spend")))
    return bytes.fromhex(v["compiledCode"])

def main():
    live = "--live" in sys.argv
    if live and "CHIRAL_CHAIN_ROOT" not in os.environ:
        sys.exit("set CHIRAL_CHAIN_ROOT (anchor tip CKB block hash; advance_relayer.py init -> state.chain_root) before --live")
    assert len(bytes.fromhex(CHAIN_ROOT)) == 32 and len(bytes.fromhex(WINDOW_ROOT)) == 32, "CHAIN_ROOT/WINDOW_ROOT must be 32 bytes"
    ctx = cardano_net.chain_context()
    sk, vk, addr = cardano_net.account()
    governor = vk.hash().payload.hex()                  # the governor = the relayer payment key hash (28B)
    print("address:", addr, "\ngovernor (relayer cred):", governor)

    subprocess.run([d6.AIKEN, "build"], cwd=HERE, check=True, capture_output=True)
    # ckpt_registry(governor) -> reg_script (the address the STABLE checkpoint cell sits at)
    reg_script = d6.apply_chain("ckpt_registry", "ckpt_registry", [d6.C_bytes(governor)], "ckpr")
    # pinned Checkpoint datum (param to ckbcert_thread AND the output datum - byte-identical)
    pinned_struct = d6.constr(0, [bytes.fromhex(CHAIN_ROOT), bytes.fromhex(TOTAL_DIFF), bytes.fromhex(WINDOW_ROOT), TIP_HEIGHT])
    pinned_param = cbor2.dumps(pinned_struct).hex()
    # REUSE ckbcert_thread(gref, pinned, cp_script=reg_script) -> the STABLE registry NFT (a fresh lineage,
    # distinct from the advance checkpoint NFT because cp_script differs)
    if live:
        us = ctx.utxos(str(addr))
        pure = sorted([u for u in us if not u.output.amount.multi_asset], key=lambda u: int(u.output.amount.coin))
        if len(pure) < 2:
            sys.exit("need >=2 pure-ADA UTxOs (a gref+funding and a collateral); split the wallet first")
        seed = pure[-1]
        collateral = next((u for u in pure if int(u.output.amount.coin) >= 5_000_000 and u.input != seed.input), None)
        if collateral is None:
            sys.exit("need a pure-ADA UTxO >= 5 ADA (distinct from the seed) for collateral")
        gref_txid = str(seed.input.transaction_id); gref_ix = seed.input.index
    else:
        gref_txid = "00" * 32; gref_ix = 0                # dry: a placeholder gref just to parameterize
    registry_nft = d6.apply_chain("ckbcert_thread", "ckbcert_thread",
                                  [d6.C_oref(gref_txid, gref_ix), pinned_param, d6.C_bytes(reg_script)], "ckbcr")
    thread_script = pc.PlutusV3Script(compiled("ckbcr", 3, "ckbcert_thread"))
    assert pc.script_hash(thread_script).payload.hex() == registry_nft, "thread script hash != derived registry NFT"

    reg_addr = pc.Address(payment_part=pc.ScriptHash(bytes.fromhex(reg_script)), network=pc.Network.TESTNET)
    nft = pc.MultiAsset.from_primitive({bytes.fromhex(registry_nft): {THREAD_NAME: 1}})
    checkpoint_datum = pc.RawPlutusData(pinned_struct)
    print("ckpt_registry script:", reg_script)
    print("REGISTRY_NFT:", registry_nft)
    print("pinned: window_root", WINDOW_ROOT[:16], "tip", TIP_HEIGHT)

    if not live:
        print("\n[dry] would mint 1 stable registry NFT -> checkpoint cell at", reg_script, "(re-run with --live)")
        return

    b = pc.TransactionBuilder(ctx)
    b.add_input(seed)
    b.add_input_address(addr)
    b.mint = nft
    b.add_minting_script(thread_script, pc.Redeemer(pc.RawPlutusData(cbor2.CBORTag(121, [])), EXU))
    b.add_output(pc.TransactionOutput(reg_addr, pc.Value(OUT_ADA, nft), datum=checkpoint_datum))
    b.collaterals = [collateral]
    tx = b.build_and_sign([sk], change_address=addr)
    txid = ctx.submit_tx(tx)
    print("\nLIVE ckpt_registry genesis submitted - preview tx:", txid)

    od = os.path.join(ROOT, "deployed", "cardano", "preview")
    os.makedirs(od, exist_ok=True)
    out = {"registry_nft": registry_nft, "registry_script": reg_script, "registry_addr": str(reg_addr),
           "governor": governor, "genesis_tx": txid, "gref": f"{gref_txid}#{gref_ix}", "thread_name_hex": THREAD_NAME.hex(),
           "pinned": {"chain_root": CHAIN_ROOT, "total_difficulty": TOTAL_DIFF, "window_root": WINDOW_ROOT, "tip_height": TIP_HEIGHT}}
    json.dump(out, open(os.path.join(od, "ckpt-registry.json"), "w"), indent=2)
    print("  state -> deployed/cardano/preview/ckpt-registry.json")

if __name__ == "__main__":
    main()
