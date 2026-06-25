#!/usr/bin/env python3
"""redeploy_seal_rl.py - re-deploy ONLY the seal registry + ratelimit cell after the SMT depth 256->128 change.

The depth change alters seal_nullifier's hash -> seal_registry_nft -> leap_mint_guard -> leap_ratelimit addr.
checkpoint, policy, and cardano_bound do NOT depend on the seal registry, so they are REUSED unchanged (a
re-genesis of policy would change cardano_bound and orphan the existing BoundState UTxO). This re-genesis seal
(SealSet @ the new empty_root 923d2522) + ratelimit (RateState 0,0 @ the new leap_ratelimit addr), re-derives
leap_mint_guard, asserts cardano_bound is unchanged, and rewrites groth16-deploy.json.

  python3 redeploy_seal_rl.py            # dry: derive + print (no submit)
  python3 redeploy_seal_rl.py --live     # re-genesis seal + ratelimit
"""
import os, sys, json, subprocess
HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "..", "..", "cardano", "binding"))
import cbor2, pycardano as pc, cardano_net, d6_deploy as d6
import genesis_threads as gt   # reuse compiled/addr_of/wait_seen/mint_one/gref_cbor + THREAD_NAME/VK/FIN_VK

PRE = os.path.join(HERE, "..", "..", "..", "deployed", "cardano", "preview")
M = json.load(open(os.path.join(PRE, "groth16-deploy.json")))
EMPTY_ROOT_128 = "923d2522a06a9d91e5e045a357cbb594cf1c39a44f050841154ae67f3acd6cbf"

def main():
    live = "--live" in sys.argv
    ctx = cardano_net.chain_context(); sk, vk, a = cardano_net.account()
    subprocess.run([d6.AIKEN, "build"], cwd=HERE, check=True, capture_output=True)
    # REUSE (unchanged): policy (from its original gref) + checkpoint + cardano_bound
    reg = d6.apply_chain("seal_nullifier", "seal_nullifier", [], "seal")                       # NEW (depth 128)
    policy_nft = d6.apply_chain("chiral_policy_thread", "chiral_policy_thread", [gt.gref_cbor(M["policy_gref"])], "cpt")
    policy_script = d6.apply_chain("chiral_policy", "chiral_policy", [d6.C_bytes(policy_nft), d6.C_bytes(d6.POLICY_NAME)], "pol")
    bound = d6.apply_chain("cardano_bound", "cardano_bound",
                           [d6.C_vk(gt.VK), d6.C_vk(gt.FIN_VK), d6.C_bytes(M["checkpoint_nft"]), d6.C_bytes(policy_nft), d6.C_bytes(d6.POLICY_NAME), d6.C_bytes(policy_script)], "bound")
    assert policy_nft == M["policy_nft"] and bound == M["cardano_bound_script"], "policy/bound drifted -- abort"

    # 1) SEAL registry re-genesis (new empty_root datum)
    us = ctx.utxos(str(a)); pure = sorted([u for u in us if not u.output.amount.multi_asset], key=lambda u: int(u.output.amount.coin))
    seal_gref = f"{str(pure[-1].input.transaction_id)}#{pure[-1].input.index}"
    seal_nft = d6.apply_chain("seal_thread", "seal_thread", [gt.gref_cbor(seal_gref), d6.C_bytes(reg)], "sealt")
    seal_script = gt.compiled("sealt", 2, "seal_thread")
    seal_datum = d6.constr(0, [bytes.fromhex(EMPTY_ROOT_128)])
    print(f"[seal] reg_script {reg}  nft {seal_nft}  -> addr {gt.addr_of(reg)}")
    if live:
        txid, used = gt.mint_one(ctx, sk, a, seal_nft, seal_script, cbor2.CBORTag(121, []), gt.addr_of(reg), seal_datum, True)
        print("  seal tx:", txid); gt.wait_seen(ctx, a, txid); seal_gref = used

    # 2) RATELIMIT re-genesis (needs the new mint_guard chain)
    us = ctx.utxos(str(a)); pure = sorted([u for u in us if not u.output.amount.multi_asset], key=lambda u: int(u.output.amount.coin))
    rl_gref = f"{str(pure[-1].input.transaction_id)}#{pure[-1].input.index}"
    rl_thread = d6.apply_chain("leap_ratelimit_thread", "leap_ratelimit_thread", [gt.gref_cbor(rl_gref)], "rlt")
    rlt_script = gt.compiled("rlt", 1, "leap_ratelimit_thread")
    mint_guard = d6.apply_chain("leap_mint_guard", "leap_mint_guard",
                                [d6.C_bytes(d6.FT_NAME), d6.C_bytes(bound), d6.C_bytes(policy_nft), d6.C_bytes(d6.POLICY_NAME), d6.C_bytes(seal_nft), d6.C_bytes(rl_thread)], "mg")
    rl_script = d6.apply_chain("leap_ratelimit", "leap_ratelimit",
                               [d6.C_bytes(rl_thread), d6.C_bytes(mint_guard), d6.C_bytes(d6.FT_NAME), d6.C_int(d6.CAP), d6.C_int(d6.WINDOW_LEN)], "rl")
    rate_datum = d6.constr(0, [0, 0])
    print(f"[ratelimit] nft {rl_thread}  -> addr {gt.addr_of(rl_script)}  | mint_guard {mint_guard}")
    if live:
        txid, used = gt.mint_one(ctx, sk, a, rl_thread, rlt_script, cbor2.CBORTag(121, []), gt.addr_of(rl_script), rate_datum, True)
        print("  ratelimit tx:", txid); gt.wait_seen(ctx, a, txid); rl_gref = used

    M.update(seal_nullifier_script=reg, seal_registry_nft=seal_nft, seal_gref=seal_gref,
             ratelimit_thread=rl_thread, leap_ratelimit_script=rl_script, ratelimit_gref=rl_gref,
             leap_mint_guard_policy=mint_guard, smt_depth=128, seal_empty_root=EMPTY_ROOT_128)
    if live:
        json.dump(M, open(os.path.join(PRE, "groth16-deploy.json"), "w"), indent=2)
        print("\nRE-DEPLOYED. new seal_registry_nft", seal_nft, "| new leap_mint_guard", mint_guard)
    else:
        print("\n[dry] new mint_guard", mint_guard, "| re-run --live")

if __name__ == "__main__":
    main()
