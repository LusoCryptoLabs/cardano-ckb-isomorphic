#!/usr/bin/env python3
"""advance_tx.py - the LIVE AdvanceCKBCert tx: spend the ckbcert checkpoint cell under advance_ckbcert with a
real advance_live Groth16 proof, producing the CONTINUING checkpoint at the advanced state (new chain_root =
new tip hash, new total_difficulty, new window_root, new tip_height). Moves the checkpoint forward so per-leap
proofs can bind a fresh window. The advance is PERMISSIONLESS (anyone with a valid proof advances; the thread
token + heaviest-chain rule keep the single pinned lineage canonical).

Inputs:
  deployed/cardano/preview/ckbcert-genesis.json   (advance_ckbcert_script, checkpoint_nft, advance_addr, pinned)
  the advance proof redeemer (advance_live PROVE=1 CEREMONY_PK=advance_live_pk.bin): proof + public_inputs_dec +
  new_state {chain_root, total_difficulty, window_root, tip_height}

  advance_tx.py --refscript            # publish advance_ckbcert as a reference script (once; fits the size limit)
  advance_tx.py <redeemer.json>            # dry: derive + build (no submit)
  advance_tx.py <redeemer.json> --live     # spend the checkpoint -> continuing checkpoint at the new state
"""
import os, sys, json, subprocess
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, "..", "..", ".."))
sys.path.insert(0, HERE); sys.path.insert(0, os.path.join(ROOT, "cardano", "binding"))
import cbor2, pycardano as pc, cardano_net, d6_deploy as d6
from pycardano.serialization import ByteString    # chunks bytestrings > 64B (proof.b = 96B G2)

PRE = os.path.join(ROOT, "deployed", "cardano", "preview")
CKBC = json.load(open(os.path.join(PRE, "ckbcert-genesis.json")))
CER = os.path.join(HERE, "..", "circuit", "ceremony")
VK = json.load(open(os.path.join(CER, "advance_live_ceremony_redeemer.json")))["vk"]   # the baked advance vk
THREAD_NAME = bytes.fromhex("636b62636572742d746872656164")
TN = pc.Network.TESTNET
EXU = pc.ExecutionUnits(1_200_000, 5_000_000_000)   # one Groth16 verify (7 inputs) + binds; tune if eval rejects
REF_PATH = os.path.join(PRE, "advance-refscript.json")
FR_ORDER = 52435875175126190479447740508185965837690552500527637822603658699938581184513  # BLS12-381 scalar field

def addr(h): return pc.Address(payment_part=pc.ScriptHash(bytes.fromhex(h)), network=TN)
def constr(i, fs): return cbor2.CBORTag(121 + i, fs)
def field_of_le(hexstr):  # == ckbcert.ak field_of: bytearray_to_integer(little-endian) % fr_order
    return int.from_bytes(bytes.fromhex(hexstr), "little") % FR_ORDER

def decode_checkpoint_datum(out):
    """Best-effort decode of the live checkpoint inline datum -> (chain_root, total_difficulty, window_root, tip_height)."""
    d = out.datum
    raw = d.to_cbor() if hasattr(d, "to_cbor") else (d.cbor if hasattr(d, "cbor") else bytes(d))
    tag = cbor2.loads(raw)
    f = tag.value
    return f[0].hex(), f[1].hex(), f[2].hex(), int(f[3])

def compiled(label, n, name):
    bp = json.load(open(f"{d6.WORK}/{label}_{n}.json"))
    v = next(x for x in bp["validators"] if x["title"].startswith(name + ".") and (x["title"].endswith(".mint") or x["title"].endswith(".spend")))
    return pc.PlutusV3Script(bytes.fromhex(v["compiledCode"]))

def derive_advance_script():
    subprocess.run([d6.AIKEN, "build"], cwd=HERE, check=True, capture_output=True)
    cp = d6.apply_chain("advance_ckbcert", "advance_ckbcert", [d6.C_vk(VK)], "adv")
    assert cp == CKBC["advance_ckbcert_script"], f"derived advance_ckbcert {cp} != deployed {CKBC['advance_ckbcert_script']} (vk drift)"
    return compiled("adv", 1, "advance_ckbcert")

def find_checkpoint(ctx, address):
    pol = pc.ScriptHash(bytes.fromhex(CKBC["checkpoint_nft"]))
    for u in ctx.utxos(str(address)):
        ma = u.output.amount.multi_asset
        if ma and pol in ma and pc.AssetName(THREAD_NAME) in ma[pol]:
            return u
    return None

def main():
    ctx = cardano_net.chain_context(); sk, vk, a = cardano_net.account()
    adv_addr = addr(CKBC["advance_ckbcert_script"])
    script = derive_advance_script()

    if "--refscript" in sys.argv:
        b = pc.TransactionBuilder(ctx); b.add_input_address(a)
        b.add_output(pc.TransactionOutput(a, pc.Value(60_000_000), script=script))
        tx = b.build_and_sign([sk], change_address=a); txid = ctx.submit_tx(tx)
        json.dump({"tx": txid, "ix": 0}, open(REF_PATH, "w"))
        print("advance_ckbcert reference script deployed:", txid, "#0  ->", REF_PATH); return

    redeemer_path = next((x for x in sys.argv[1:] if x.endswith(".json") and "advance" in os.path.basename(x).lower()), None) \
        or next((x for x in sys.argv[1:] if x.endswith(".json")), None)
    assert redeemer_path, "pass the advance_live redeemer json"
    RED = json.load(open(redeemer_path))
    # GUARD 1: the proof must verify under the BAKED (ceremony) vk, not a seeded/test vk -> else snark_ok fails on-chain.
    assert RED.get("vk") == VK, "redeemer vk != baked advance vk (wrong/test redeemer); regenerate with CEREMONY_PK=advance_live_pk.bin"
    pr = RED["proof"]; PI = [int(x) for x in RED["public_inputs_dec"]]; ns = RED["new_state"]
    new_chain_root = bytes.fromhex(ns["chain_root"])
    new_total = bytes.fromhex(ns["total_difficulty"])
    new_wroot = bytes.fromhex(ns["window_root"])
    new_tip = int(ns["tip_height"])
    assert len(new_chain_root) == 32 and len(new_total) == 32 and len(new_wroot) == 32, "32-byte fields"

    ck_in = find_checkpoint(ctx, adv_addr)
    assert ck_in, f"checkpoint cell (nft {CKBC['checkpoint_nft'][:12]}) not found at {adv_addr}"
    # GUARD 2: the proof's OLD side must equal field_of() of the LIVE checkpoint datum, and new_tip > cp.tip,
    # else advance_ckbcert.bound_ok / cont_ok fail on-chain (burning collateral). Catch it OFF-chain here.
    try:
        cp_cr, cp_td, cp_wr, cp_th = decode_checkpoint_datum(ck_in.output)
        assert field_of_le(cp_cr) == PI[0], f"PI[0] {PI[0]} != field_of(cp.chain_root)"
        assert field_of_le(cp_td) == PI[1], f"PI[1] {PI[1]} != field_of(cp.total_difficulty)"
        assert field_of_le(cp_wr) == PI[4], f"PI[4] {PI[4]} != field_of(cp.window_root)"
        assert new_tip > cp_th, f"new_tip {new_tip} not > live cp.tip_height {cp_th} (cont_ok would fail)"
        print(f"  [guard] live checkpoint datum binds the proof old-side; cp.tip={cp_th} -> {new_tip}")
    except AssertionError:
        raise
    except Exception as e:
        # if the datum can't be decoded from this context, fall back to the manifest/state assertion below
        print(f"  [guard] WARN: could not decode live checkpoint datum ({e}); relying on --state / manifest")
        st_path = next((x for x in sys.argv[1:] if x.endswith(".json") and "state" in os.path.basename(x).lower()), None)
        ref = json.load(open(st_path)) if st_path else CKBC.get("pinned", {})
        assert ref, "no --state file and no manifest pinned state to cross-check the redeemer old-side"
        assert field_of_le(ref["chain_root"]) == PI[0] and field_of_le(ref["total_difficulty"]) == PI[1] \
            and field_of_le(ref["window_root"]) == PI[4] and new_tip > int(ref["tip_height"]), \
            "redeemer old-side != current state (chain_root/total/window_root/tip) -- stale or wrong proof"
    nft = pc.MultiAsset.from_primitive({bytes.fromhex(CKBC["checkpoint_nft"]): {THREAD_NAME: 1}})
    # Advance redeemer: { proof, new_chain_root, new_total_difficulty, new_window_root, new_tip_height, public_inputs }
    proof = constr(0, [bytes.fromhex(pr["a"]), ByteString(bytes.fromhex(pr["b"])), bytes.fromhex(pr["c"])])
    advance = pc.RawPlutusData(constr(0, [proof, new_chain_root, new_total, new_wroot, new_tip, PI]))
    # continuing checkpoint datum: Checkpoint{ chain_root, total_difficulty, window_root, tip_height }
    new_datum = pc.RawPlutusData(constr(0, [new_chain_root, new_total, new_wroot, new_tip]))

    b = pc.TransactionBuilder(ctx)
    b.add_input_address(a)
    # spend via reference script if published, else inline
    if os.path.exists(REF_PATH):
        rf = json.load(open(REF_PATH))
        ref = pc.UTxO(pc.TransactionInput(pc.TransactionId(bytes.fromhex(rf["tx"])), rf["ix"]),
                      pc.TransactionOutput(a, pc.Value(60_000_000), script=script))
        b.add_script_input(ck_in, script=ref, redeemer=pc.Redeemer(advance, EXU))
    else:
        b.add_script_input(ck_in, script=script, redeemer=pc.Redeemer(advance, EXU))
    # the continuing checkpoint: same address, SAME thread token (qty 1), advanced datum
    b.add_output(pc.TransactionOutput(adv_addr, pc.Value(int(ck_in.output.amount.coin), nft), datum=new_datum))
    pure = sorted([u for u in ctx.utxos(str(a)) if not u.output.amount.multi_asset], key=lambda u: int(u.output.amount.coin))
    b.collaterals = [pure[0]]
    if "--live" not in sys.argv:
        body = b.build(change_address=a)
        print(f"[dry] advance tip -> {new_tip}  new chain_root={ns['chain_root'][:16]}  window_root={ns['window_root'][:16]}  outputs={len(body.outputs)}")
        return
    tx = b.build_and_sign([sk], change_address=a)
    txid = ctx.submit_tx(tx)
    print(f"\nADVANCE submitted -- preview tx: {txid}  | checkpoint tip -> {new_tip}  window_root {ns['window_root'][:16]}")
    log = os.path.join(PRE, "advance-log.json")
    hist = json.load(open(log)) if os.path.exists(log) else []
    hist.append({"tx": txid, "tip_height": new_tip, "chain_root": ns["chain_root"], "window_root": ns["window_root"]})
    json.dump(hist, open(log, "w"), indent=2)
    print("  state -> deployed/cardano/preview/advance-log.json")

if __name__ == "__main__":
    main()
