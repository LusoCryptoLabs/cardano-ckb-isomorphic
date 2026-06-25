#!/usr/bin/env python3
"""ckpt_reanchor.py - E2: GOVERNOR-gated TRUSTED re-anchor of the stable checkpoint-registry cell.

Spends the registry cell via ckpt_registry.ReAnchor to a fresh CKB anchor {chain_root, total_difficulty,
window_root, tip_height}, preserving the stable thread NFT (continuity) with a MONOTONIC tip - REPLACING the
per-return genesis_ckbcert re-mint (which churned the escrow). No PoW proof: this is the trusted advance,
IDENTICAL trust to today's per-return re-genesis, authorized by the governor signature (the relayer key).

  python3 ckpt_reanchor.py            # dry: derive the script + build the redeemer (no cell needed, no submit)
  CHIRAL_CHAIN_ROOT=.. CHIRAL_WINDOW_ROOT=.. CHIRAL_TIP_HEIGHT=.. [CHIRAL_TOTAL_DIFF=..] python3 ckpt_reanchor.py --live
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

PRE = os.path.join(ROOT, "deployed", "cardano", "preview")
THREAD_NAME = bytes.fromhex("636b62636572742d746872656164")
EXU = pc.ExecutionUnits(1_200_000, 400_000_000)         # light: governor sig + lineage continuity (no SNARK)

def compiled(label, n, name):
    bp = json.load(open(f"{d6.WORK}/{label}_{n}.json"))
    v = next(x for x in bp["validators"] if x["title"].startswith(name + ".") and x["title"].endswith(".spend"))
    return bytes.fromhex(v["compiledCode"])

def read_checkpoint(datum):
    raw = datum.to_cbor() if hasattr(datum, "to_cbor") else (datum.cbor if hasattr(datum, "cbor") else bytes(datum))
    return cbor2.loads(raw).value                        # [chain_root, total_difficulty, window_root, tip_height]

def main():
    live = "--live" in sys.argv
    NEW_WINDOW = os.environ.get("CHIRAL_WINDOW_ROOT", "6f01df31e1fe4b799e95d7e59f5ae8ce57f3cf94945bcf5f76c67da050cf2f85")
    NEW_TIP    = int(os.environ.get("CHIRAL_TIP_HEIGHT", "21388354"))
    NEW_CHAIN  = os.environ.get("CHIRAL_CHAIN_ROOT", "00" * 32)
    NEW_DIFF   = os.environ.get("CHIRAL_TOTAL_DIFF", "00" * 32)
    assert all(len(bytes.fromhex(x)) == 32 for x in (NEW_WINDOW, NEW_CHAIN, NEW_DIFF)), "roots must be 32 bytes"

    ctx = cardano_net.chain_context()
    sk, vk, addr = cardano_net.account()
    governor = vk.hash().payload.hex()

    subprocess.run([d6.AIKEN, "build"], cwd=HERE, check=True, capture_output=True)
    reg_script = d6.apply_chain("ckpt_registry", "ckpt_registry", [d6.C_bytes(governor)], "ckpr")
    spend_script = pc.PlutusV3Script(compiled("ckpr", 1, "ckpt_registry"))
    assert pc.script_hash(spend_script).payload.hex() == reg_script
    reg_addr = pc.Address(payment_part=pc.ScriptHash(bytes.fromhex(reg_script)), network=pc.Network.TESTNET)

    # the new Checkpoint datum AND the ReAnchor redeemer carry the SAME fresh anchor (the validator checks the
    # continuing output's datum == the redeemer fields).
    new_struct = d6.constr(0, [bytes.fromhex(NEW_CHAIN), bytes.fromhex(NEW_DIFF), bytes.fromhex(NEW_WINDOW), NEW_TIP])
    reanchor = d6.constr(0, [bytes.fromhex(NEW_CHAIN), bytes.fromhex(NEW_DIFF), bytes.fromhex(NEW_WINDOW), NEW_TIP])
    print("ckpt_registry script:", reg_script, "\ngovernor:", governor, "\nnew anchor tip:", NEW_TIP, "window_root:", NEW_WINDOW[:16])

    if not live:
        # cross-check against the deployed registry if genesis already ran
        reg = json.load(open(os.path.join(PRE, "ckpt-registry.json"))) if os.path.exists(os.path.join(PRE, "ckpt-registry.json")) else None
        if reg:
            print("[dry] deployed registry_script:", reg["registry_script"], "match:", reg["registry_script"] == reg_script)
        print("[dry] reanchor redeemer cbor:", cbor2.dumps(reanchor).hex())
        print("[dry] re-run with --live (needs the genesis'd registry cell) to submit")
        return

    reg = json.load(open(os.path.join(PRE, "ckpt-registry.json")))
    registry_nft = reg["registry_nft"]
    assert reg["registry_script"] == reg_script, "deployed registry_script != derived (governor changed?)"
    assert governor == reg["governor"], "signer is not the genesis governor"
    nft_sh = pc.ScriptHash(bytes.fromhex(registry_nft))
    cell = next((u for u in ctx.utxos(str(reg_addr))
                 if u.output.amount.multi_asset and nft_sh in u.output.amount.multi_asset), None)
    if cell is None:
        sys.exit("live registry cell (carrying the NFT) not found at " + reg_script)
    cur = read_checkpoint(cell.output.datum)
    cur_tip = int(cur[3])
    cur_wroot = cur[2].hex() if isinstance(cur[2], (bytes, bytearray)) else str(cur[2])
    if NEW_TIP <= cur_tip:
        # IDEMPOTENT: if the cell already sits at this exact anchor (same tip + window_root), it's a no-op -
        # the orchestrator may re-run the same burn, and the registry already covers it. Only a STRICT rollback
        # (a different/earlier anchor) is rejected.
        if NEW_TIP == cur_tip and cur_wroot == NEW_WINDOW:
            print(f"already anchored at tip {cur_tip} (window {NEW_WINDOW[:16]}…); skipping re-anchor (no-op)")
            return
        sys.exit(f"non-monotonic re-anchor: new tip {NEW_TIP} <= current {cur_tip} (and window differs - rollback refused)")
    print(f"re-anchoring tip {cur_tip} -> {NEW_TIP}")

    nft = pc.MultiAsset.from_primitive({bytes.fromhex(registry_nft): {THREAD_NAME: 1}})
    pure = sorted([u for u in ctx.utxos(str(addr)) if not u.output.amount.multi_asset], key=lambda u: int(u.output.amount.coin))
    collateral = next((u for u in pure if int(u.output.amount.coin) >= 5_000_000), None)
    if collateral is None:
        sys.exit("need a pure-ADA UTxO >= 5 ADA for collateral; consolidate the wallet")
    b = pc.TransactionBuilder(ctx)
    b.add_script_input(cell, script=spend_script, redeemer=pc.Redeemer(pc.RawPlutusData(reanchor), EXU))
    b.add_input_address(addr)
    b.add_output(pc.TransactionOutput(reg_addr, pc.Value(int(cell.output.amount.coin), nft), datum=pc.RawPlutusData(new_struct)))
    b.collaterals = [collateral]
    b.required_signers = [vk.hash()]
    tx = b.build_and_sign([sk], change_address=addr)
    txid = ctx.submit_tx(tx)
    print("\nLIVE re-anchor submitted - preview tx:", txid, "| tip ->", NEW_TIP)
    reg["pinned"] = {"chain_root": NEW_CHAIN, "total_difficulty": NEW_DIFF, "window_root": NEW_WINDOW, "tip_height": NEW_TIP}
    reg["last_reanchor_tx"] = txid
    json.dump(reg, open(os.path.join(PRE, "ckpt-registry.json"), "w"), indent=2)
    print("  state -> deployed/cardano/preview/ckpt-registry.json")

if __name__ == "__main__":
    main()
