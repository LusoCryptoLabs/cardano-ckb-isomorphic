#!/usr/bin/env python3
"""genesis_threads.py - LIVE genesis of the remaining 3 Groth16-leg singletons on Cardano preview:
  seal      : seal_thread NFT -> SealSet{empty_root} cell at the seal_nullifier address
  policy    : chiral_policy_thread NFT -> PolicyState{governor, sane caps, K=12} cell at chiral_policy
  ratelimit : leap_ratelimit_thread NFT -> RateState{0,0} cell at leap_ratelimit
Each is a one-shot Plutus mint (consume the largest UTxO as gref, reuse the smallest as collateral), done
SEQUENTIALLY with confirmation waits. The ratelimit address depends on the full mint_guard chain, so this
derives EVERYTHING (using the already-live checkpoint_nft e66554ae) and writes deployed/cardano/preview/
groth16-deploy.json - the manifest the leap tx consumes.

  python3 genesis_threads.py            # dry: derive + print all addrs/NFTs (no submit)
  python3 genesis_threads.py --live     # mint seal, policy, ratelimit in sequence
"""
import os, sys, json, subprocess, time
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, "..", "..", ".."))
sys.path.insert(0, HERE); sys.path.insert(0, os.path.join(ROOT, "cardano", "binding"))
import cbor2, pycardano as pc, cardano_net, d6_deploy as d6

CER = os.path.join(HERE, "..", "circuit", "ceremony")
VK = json.load(open(os.path.join(CER, "leap_bound_windowed_redeemer.json")))["vk"]
FIN_VK = json.load(open(os.path.join(CER, "finalize_windowed_redeemer.json")))["vk"]
CKBC = json.load(open(os.path.join(ROOT, "deployed", "cardano", "preview", "ckbcert-genesis.json")))
CHECKPOINT_NFT = CKBC["checkpoint_nft"]                                   # read at runtime from ckbcert-genesis.json (picks up a fresh re-genesis)
EMPTY_ROOT = "923d2522a06a9d91e5e045a357cbb594cf1c39a44f050841154ae67f3acd6cbf"   # == seal_set.empty_root() (DEPTH=128, recomputed; old 8a95af78 was for the pre-128 tree)
THREAD_NAME = bytes.fromhex("636b62636572742d746872656164")
MAX_AMOUNT = 10_000_000_000_000        # 100,000 CKB per-leap cap (within d6 caps; 200 CKB leap fits)
K = 12
EXU = pc.ExecutionUnits(6_000_000, 2_000_000_000)
FALSE = d6.constr(0, [])               # Plutus Bool False

def compiled(label, n, name):
    bp = json.load(open(f"{d6.WORK}/{label}_{n}.json"))
    v = next(x for x in bp["validators"] if x["title"].startswith(name + ".") and (x["title"].endswith(".mint") or x["title"].endswith(".spend")))
    return pc.PlutusV3Script(bytes.fromhex(v["compiledCode"]))

def addr_of(h): return pc.Address(payment_part=pc.ScriptHash(bytes.fromhex(h)), network=pc.Network.TESTNET)

def wait_seen(ctx, addr, txid, tries=40):
    for _ in range(tries):
        for u in ctx.utxos(str(addr)):
            if str(u.input.transaction_id) == txid:
                return
        time.sleep(12)
    raise TimeoutError(f"tx {txid} not seen")

def mint_one(ctx, sk, addr, policy_id, script, redeemer_cbor, out_addr, datum_struct, live):
    us = ctx.utxos(str(addr))
    pure = sorted([u for u in us if not u.output.amount.multi_asset], key=lambda u: int(u.output.amount.coin))
    collateral, gref = pure[0], pure[-1]
    nft = pc.MultiAsset.from_primitive({bytes.fromhex(policy_id): {THREAD_NAME: 1}})
    if not live:
        return None, f"{str(gref.input.transaction_id)}#{gref.input.index}"
    b = pc.TransactionBuilder(ctx)
    b.add_input(gref); b.add_input_address(addr)
    b.mint = nft
    b.add_minting_script(script, pc.Redeemer(pc.RawPlutusData(redeemer_cbor), EXU))
    b.add_output(pc.TransactionOutput(out_addr, pc.Value(5_000_000, nft), datum=pc.RawPlutusData(datum_struct)))
    b.collaterals = [collateral]
    tx = b.build_and_sign([sk], change_address=addr)
    txid = ctx.submit_tx(tx)
    return txid, f"{str(gref.input.transaction_id)}#{gref.input.index}"

def gref_cbor(gref_str):
    txid, ix = gref_str.split("#"); return d6.C_oref(txid, int(ix))

def main():
    live = "--live" in sys.argv
    ctx = cardano_net.chain_context(); sk, vk, addr = cardano_net.account()
    gov = vk.hash().payload.hex()
    subprocess.run([d6.AIKEN, "build"], cwd=HERE, check=True, capture_output=True)
    reg_script = d6.apply_chain("seal_nullifier", "seal_nullifier", [], "seal")   # 0 params -> fixed
    M = {"checkpoint_nft": CHECKPOINT_NFT, "seal_nullifier_script": reg_script, "governor_vkh": gov}

    # ---- 1) SEAL registry (self-contained) ----
    us = ctx.utxos(str(addr)); pure = sorted([u for u in us if not u.output.amount.multi_asset], key=lambda u: int(u.output.amount.coin))
    seal_gref = f"{str(pure[-1].input.transaction_id)}#{pure[-1].input.index}"
    seal_nft = d6.apply_chain("seal_thread", "seal_thread", [gref_cbor(seal_gref), d6.C_bytes(reg_script)], "sealt")
    seal_script = compiled("sealt", 2, "seal_thread")
    seal_datum = d6.constr(0, [bytes.fromhex(EMPTY_ROOT)])
    print(f"[seal] gref {seal_gref}  nft {seal_nft}  -> addr {addr_of(reg_script)}")
    if live:
        txid, used = mint_one(ctx, sk, addr, seal_nft, seal_script, cbor2.CBORTag(121, []), addr_of(reg_script), seal_datum, True)
        print("  seal genesis tx:", txid); wait_seen(ctx, addr, txid); seal_gref = used
    M.update(seal_registry_nft=seal_nft, seal_gref=seal_gref, seal_genesis_tx=(txid if live else None))

    # ---- 2) POLICY cell ----
    us = ctx.utxos(str(addr)); pure = sorted([u for u in us if not u.output.amount.multi_asset], key=lambda u: int(u.output.amount.coin))
    pol_gref = f"{str(pure[-1].input.transaction_id)}#{pure[-1].input.index}"
    policy_nft = d6.apply_chain("chiral_policy_thread", "chiral_policy_thread", [gref_cbor(pol_gref)], "cpt")
    cpt_script = compiled("cpt", 1, "chiral_policy_thread")
    policy_script = d6.apply_chain("chiral_policy", "chiral_policy", [d6.C_bytes(policy_nft), d6.C_bytes(d6.POLICY_NAME)], "pol")
    guard = d6.constr(0, [FALSE, FALSE, FALSE, 0, MAX_AMOUNT, K])             # GuardPolicy
    policy_datum = d6.constr(0, [bytes.fromhex(gov), guard])                  # PolicyState
    print(f"[policy] gref {pol_gref}  nft {policy_nft}  -> addr {addr_of(policy_script)}")
    if live:
        txid, used = mint_one(ctx, sk, addr, policy_nft, cpt_script, cbor2.CBORTag(121, []), addr_of(policy_script), policy_datum, True)
        print("  policy genesis tx:", txid); wait_seen(ctx, addr, txid); pol_gref = used
    M.update(policy_nft=policy_nft, policy_script=policy_script, policy_gref=pol_gref, policy_genesis_tx=(txid if live else None))

    # ---- 3) RATELIMIT cell (needs the full mint_guard chain) ----
    us = ctx.utxos(str(addr)); pure = sorted([u for u in us if not u.output.amount.multi_asset], key=lambda u: int(u.output.amount.coin))
    rl_gref = f"{str(pure[-1].input.transaction_id)}#{pure[-1].input.index}"
    rl_thread = d6.apply_chain("leap_ratelimit_thread", "leap_ratelimit_thread", [gref_cbor(rl_gref)], "rlt")
    rlt_script = compiled("rlt", 1, "leap_ratelimit_thread")
    bound = d6.apply_chain("cardano_bound", "cardano_bound",
                           [d6.C_vk(VK), d6.C_vk(FIN_VK), d6.C_bytes(CHECKPOINT_NFT), d6.C_bytes(policy_nft), d6.C_bytes(d6.POLICY_NAME), d6.C_bytes(policy_script)], "bound")
    mint_guard = d6.apply_chain("leap_mint_guard", "leap_mint_guard",
                                [d6.C_bytes(d6.FT_NAME), d6.C_bytes(bound), d6.C_bytes(policy_nft), d6.C_bytes(d6.POLICY_NAME), d6.C_bytes(seal_nft), d6.C_bytes(rl_thread)], "mg")
    rl_script = d6.apply_chain("leap_ratelimit", "leap_ratelimit",
                               [d6.C_bytes(rl_thread), d6.C_bytes(mint_guard), d6.C_bytes(d6.FT_NAME), d6.C_int(d6.CAP), d6.C_int(d6.WINDOW_LEN)], "rl")
    rate_datum = d6.constr(0, [0, 0])                                         # RateState{0,0}
    print(f"[ratelimit] gref {rl_gref}  nft {rl_thread}  -> addr {addr_of(rl_script)}")
    print(f"[derived] cardano_bound {bound}  leap_mint_guard {mint_guard}")
    if live:
        txid, used = mint_one(ctx, sk, addr, rl_thread, rlt_script, cbor2.CBORTag(121, []), addr_of(rl_script), rate_datum, True)
        print("  ratelimit genesis tx:", txid); wait_seen(ctx, addr, txid); rl_gref = used
    M.update(ratelimit_thread=rl_thread, leap_ratelimit_script=rl_script, ratelimit_gref=rl_gref,
             cardano_bound_script=bound, leap_mint_guard_policy=mint_guard, ratelimit_genesis_tx=(txid if live else None))

    if live:
        od = os.path.join(ROOT, "deployed", "cardano", "preview"); os.makedirs(od, exist_ok=True)
        json.dump(M, open(os.path.join(od, "groth16-deploy.json"), "w"), indent=2)
        print("\nALL 3 thread genesis live. manifest -> deployed/cardano/preview/groth16-deploy.json")
        print("cardano_bound:", bound, "| leap_mint_guard:", mint_guard)
    else:
        print("\n[dry] re-run with --live to mint. cardano_bound:", bound, "leap_mint_guard:", mint_guard)

if __name__ == "__main__":
    main()
