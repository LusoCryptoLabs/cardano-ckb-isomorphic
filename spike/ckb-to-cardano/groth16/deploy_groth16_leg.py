#!/usr/bin/env python3
"""deploy_groth16_leg.py - derive the FULL Groth16-leg deployment (now that both genesis-pin cycles are
broken: advance_ckbcert(vk)->cp_script->ckbcert_thread->CHECKPOINT_NFT and seal_nullifier()->reg_script->
seal_thread->SEAL_REGISTRY_NFT are ACYCLIC). Reuses d6_deploy's apply-chain machinery + the REAL ceremony VKs.

This is the DERIVE stage (no tx): it computes every real script hash + policy id + the genesis datums, using
4 candidate genesis outpoints (the wallet UTxOs). Output = a deploy manifest. The live genesis/leap submission
consumes those exact outpoints.

  python3 deploy_groth16_leg.py            # derive + print the manifest (dry)
"""
import os, sys, json, cbor2
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import d6_deploy as d6   # apply_chain, C_oref, C_bytes, C_int, C_vk, constr, POLICY_NAME, FT_NAME, CAP, WINDOW_LEN, K_DEFAULT

CER = os.path.join(HERE, "..", "circuit", "ceremony")
VK = json.load(open(os.path.join(CER, "leap_bound_windowed_redeemer.json")))["vk"]          # transition VK
FIN_VK = json.load(open(os.path.join(CER, "finalize_windowed_redeemer.json")))["vk"]        # finalize VK

# the REAL CKB window state the leap proof binds (validate_window_binding.py: field_of(window_root)==PI[0]).
WINDOW_ROOT = os.environ.get("CHIRAL_WINDOW_ROOT", "6f01df31e1fe4b799e95d7e59f5ae8ce57f3cf94945bcf5f76c67da050cf2f85")
TIP_HEIGHT  = int(os.environ.get("CHIRAL_TIP_HEIGHT", "21388353"))
# chain_root / total_difficulty are only read by advance_ckbcert (not by the leap); zeroed for the
# genesis-pinned demo checkpoint (advancing needs the advance ceremony + a redeploy - a documented follow-up).
CHAIN_ROOT = "00" * 32
TOTAL_DIFF = "00" * 32

def C_checkpoint(chain_root, total_diff, window_root, tip):
    return cbor2.dumps(d6.constr(0, [bytes.fromhex(chain_root), bytes.fromhex(total_diff),
                                     bytes.fromhex(window_root), tip])).hex()

def C_sealset(root):
    return cbor2.dumps(d6.constr(0, [bytes.fromhex(root)])).hex()

def main():
    # candidate genesis outpoints: 4 distinct wallet UTxOs (the live submit consumes these exact ones).
    grefs = json.loads(os.environ["CHIRAL_GREFS"]) if os.environ.get("CHIRAL_GREFS") else \
        [["%02x" % i * 32, i] for i in range(1, 5)]   # placeholders if not supplied (derivation still valid-shape)
    g_ckbc, g_seal, g_pol, g_rl = grefs[0], grefs[1], grefs[2], grefs[3]

    d6.aiken_build() if hasattr(d6, "aiken_build") else None
    # 1) ckbcert checkpoint lineage (ACYCLIC: advance_ckbcert(vk) -> cp_script -> ckbcert_thread -> NFT)
    cp_script = d6.apply_chain("advance_ckbcert", "advance_ckbcert", [d6.C_vk(VK)], "adv")
    pinned = C_checkpoint(CHAIN_ROOT, TOTAL_DIFF, WINDOW_ROOT, TIP_HEIGHT)
    checkpoint_nft = d6.apply_chain("ckbcert_thread", "ckbcert_thread",
                                    [d6.C_oref(*g_ckbc), pinned, d6.C_bytes(cp_script)], "ckbc")
    # 2) seal-nullifier registry lineage (ACYCLIC: seal_nullifier() -> reg_script -> seal_thread -> NFT)
    reg_script = d6.apply_chain("seal_nullifier", "seal_nullifier", [], "seal")
    seal_registry_nft = d6.apply_chain("seal_thread", "seal_thread",
                                       [d6.C_oref(*g_seal), d6.C_bytes(reg_script)], "sealt")
    # 3) the d6 chain with the REAL checkpoint_nft + seal_registry_nft
    policy_nft = d6.apply_chain("chiral_policy_thread", "chiral_policy_thread", [d6.C_oref(*g_pol)], "cpt")
    ratelimit_thread = d6.apply_chain("leap_ratelimit_thread", "leap_ratelimit_thread", [d6.C_oref(*g_rl)], "rlt")
    policy_script = d6.apply_chain("chiral_policy", "chiral_policy",
                                   [d6.C_bytes(policy_nft), d6.C_bytes(d6.POLICY_NAME)], "pol")
    bound = d6.apply_chain("cardano_bound", "cardano_bound",
                           [d6.C_vk(VK), d6.C_vk(FIN_VK), d6.C_bytes(checkpoint_nft),
                            d6.C_bytes(policy_nft), d6.C_bytes(d6.POLICY_NAME), d6.C_bytes(policy_script)], "bound")
    mint_guard = d6.apply_chain("leap_mint_guard", "leap_mint_guard",
                                [d6.C_bytes(d6.FT_NAME), d6.C_bytes(bound), d6.C_bytes(policy_nft),
                                 d6.C_bytes(d6.POLICY_NAME), d6.C_bytes(seal_registry_nft),
                                 d6.C_bytes(ratelimit_thread)], "mg")
    ratelimit_script = d6.apply_chain("leap_ratelimit", "leap_ratelimit",
                                      [d6.C_bytes(ratelimit_thread), d6.C_bytes(mint_guard), d6.C_bytes(d6.FT_NAME),
                                       d6.C_int(d6.CAP), d6.C_int(d6.WINDOW_LEN)], "rl")

    manifest = {
        "_note": "FULL Groth16-leg derivation (acyclic, REAL ceremony VKs). grefs are the 4 genesis outpoints "
                 "to consume at live genesis. chain_root/total_difficulty zeroed (advance not exercised in the "
                 "demo; advancing needs the advance ceremony + redeploy).",
        "ceremony_vk_ic": len(VK["ic"]), "finalize_vk_ic": len(FIN_VK["ic"]),
        "grefs": {"ckbcert": g_ckbc, "seal": g_seal, "policy": g_pol, "ratelimit": g_rl},
        "advance_ckbcert_script": cp_script,
        "checkpoint_nft": checkpoint_nft,
        "pinned_checkpoint": {"chain_root": CHAIN_ROOT, "total_difficulty": TOTAL_DIFF,
                              "window_root": WINDOW_ROOT, "tip_height": TIP_HEIGHT, "datum_cbor": pinned},
        "seal_nullifier_script": reg_script,
        "seal_registry_nft": seal_registry_nft,
        "chiral_policy_thread_nft": policy_nft,
        "leap_ratelimit_thread_nft": ratelimit_thread,
        "chiral_policy_script": policy_script,
        "cardano_bound_script": bound,
        "leap_mint_guard_policy": mint_guard,
        "leap_ratelimit_script": ratelimit_script,
        "params": {"ft_name": d6.FT_NAME, "policy_name": d6.POLICY_NAME, "K": d6.K_DEFAULT,
                   "cap": d6.CAP, "window_len": d6.WINDOW_LEN},
    }
    print(json.dumps(manifest, indent=2))

if __name__ == "__main__":
    main()
