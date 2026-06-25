#!/usr/bin/env python3
"""d6_deploy.py - derive the D6 deploy addresses (acyclic apply chain) + emit a deploy manifest.

Resolves the now-broken parameter circularity (minters take only genesis_ref) by applying parameters in
DEPENDENCY ORDER:

  chiral_policy_thread(gref_A)                         -> policy_nft
  leap_ratelimit_thread(gref_B)                        -> ratelimit_thread
  chiral_policy(policy_nft, policy_name)               -> policy_script
  leap_ratelimit(ratelimit_thread, ftpol, ftnm, cap, window_len) -> ratelimit_script
  cardano_bound(vk, finalize_vk, checkpoint_nft, policy_nft, policy_name, policy_script) -> bound
  leap_mint_guard(ftnm, bound, policy_nft, policy_name, seal_nullifier_hash, ratelimit_thread) -> mint_guard

INPUTS to fill at real deploy time (placeholders marked PLACEHOLDER below):
  - gref_A, gref_B : two distinct UNSPENT outpoints from the funded deployer key (consumed at genesis-mint).
  - finalize_vk    : from the FINALIZE ceremony (pending). Until then we placeholder it with the leap vk.
  - checkpoint_nft : the ckbcert_thread policy id of the deployed light-client checkpoint lineage.
  - seal_nullifier_hash : the deployed seal_nullifier script hash.
Run:  python3 d6_deploy.py            # derive + print manifest (uses placeholders -> 'derivation demo' addresses)
"""
import json, subprocess, cbor2, os, sys, shutil

HERE = os.path.dirname(os.path.abspath(__file__))
BP = os.path.join(HERE, "plutus.json")
AIKEN = os.path.expanduser("~/.aiken/bin/aiken")
WORK = "/tmp/d6deploy"; os.makedirs(WORK, exist_ok=True)

# ---- governance / FT params (deployment choices) ----
THREAD_NAME = "636b62636572742d746872656164"      # shared thread asset name "ckbcert-thread"
POLICY_NAME = THREAD_NAME                          # the policy NFT asset name (cardano_bound.policy_name)
FT_NAME     = "cf87434b42"                         # "χCKB" (U+03C7 chi 'cf87' ++ "CKB") - the leaped-CKB token on Cardano
K_DEFAULT   = 12                                   # genesis min_confirmations (sane: 0..32)
WINDOW_LEN  = 3600_000                             # rate-limiter window in POSIXTime MS (Plutus V3 validity unit); 3,600,000 ms = 1h. >= max_width 600_000

# ---- SEC D6 reorg caps - NOW ENABLED (were 0/disabled => RATELIMIT-1). Units: CKB shannons (1 CKB = 1e8).
# The AGGREGATE cap is a compile-time parameter to leap_ratelimit (baked into its script hash => immutable
# post-deploy: a captured governor key cannot lift the global safety cap). The PER-LEAP caps live in the
# governable PolicyState datum (governor-tunable on-chain). Governance invariant (leap_ratelimit.ak header):
#   window_len >= wall-clock of a depth-K reorg  AND  CAP < cost-to-rent-CKB-majority-for-window_len.
# Throughput ceiling = CAP/window_len. Tune all three via env at deploy; defaults are conservative testnet
# values (NOT economic advice for mainnet - re-derive CAP against the live rent cost before go-live).
CKB         = 100_000_000                                                  # 1 CKB in shannons
CAP         = int(os.environ.get("CHIRAL_CAP_CKB",  "1000000")) * CKB      # aggregate per-window cap (1,000,000 CKB)
MAX_AMOUNT  = int(os.environ.get("CHIRAL_MAX_CKB",  "100000"))  * CKB      # per-leap cap (100,000 CKB; 0 = none)
MIN_AMOUNT  = int(os.environ.get("CHIRAL_MIN_CKB",  "0"))       * CKB      # per-leap floor (0 = none)
assert CAP > 0, "RATELIMIT-1: aggregate cap must ship ENABLED (CAP>0)"
assert MAX_AMOUNT == 0 or MIN_AMOUNT <= MAX_AMOUNT, "sane-caps: min_amount <= max_amount (chiral_policy invariant)"

# ---- PLACEHOLDER inputs (swap at real deploy) ----
GREF_A = ("aa"*32, 0)                              # PLACEHOLDER policy-thread genesis outpoint
GREF_B = ("bb"*32, 1)                              # PLACEHOLDER ratelimit-thread genesis outpoint
CHECKPOINT_NFT = "cc"*28                           # PLACEHOLDER ckbcert_thread policy id
SEAL_REGISTRY_NFT = "dd"*28                        # PLACEHOLDER seal registry NFT (seal_thread policy id; leap_mint_guard finds the registry by THIS)

def constr(i, fields): return cbor2.CBORTag(121 + i, fields)
def C_oref(txid, idx): return cbor2.dumps(constr(0, [bytes.fromhex(txid), idx])).hex()
def C_bytes(h): return cbor2.dumps(bytes.fromhex(h)).hex()
def C_int(n): return cbor2.dumps(n).hex()
def C_vk(vk):  # VerifyingKey { alpha_g1, beta_g2, gamma_g2, delta_g2, ic: List<ByteArray> }
    fields = [bytes.fromhex(vk["alpha_g1"]), bytes.fromhex(vk["beta_g2"]), bytes.fromhex(vk["gamma_g2"]),
              bytes.fromhex(vk["delta_g2"]), [bytes.fromhex(x) for x in vk["ic"]]]
    return cbor2.dumps(constr(0, fields)).hex()

def val_hash(bp, needle):
    d = json.load(open(bp))
    for v in d["validators"]:
        if needle in v["title"]:
            return v["hash"], [p["title"] for p in v.get("parameters", [])]
    raise KeyError(needle)

def apply_chain(module, validator, params, label):
    """Apply a list of CBOR-hex params left-to-right; return the final script hash."""
    cur = shutil.copy(BP, f"{WORK}/{label}_0.json")
    for n, cbor_hex in enumerate(params):
        out = f"{WORK}/{label}_{n+1}.json"
        r = subprocess.run([AIKEN, "blueprint", "apply", "-m", module, "-v", validator, "-i", cur, "-o", out, cbor_hex],
                           capture_output=True, text=True, cwd=HERE)
        if r.returncode != 0:
            print(f"APPLY {label} param {n} FAILED:\n{r.stderr[-500:]}"); sys.exit(1)
        cur = out
    h, rem = val_hash(cur, validator)
    assert rem == [], f"{label}: {len(rem)} params left unapplied: {rem}"
    return h

def main():
    # PRODUCTION VKs from the MPC trusted-setup ceremonies (circuit/ceremony/). The transition leg is the
    # VALUE-BOUND combined circuit (leap_bound_windowed: value binding + reorg K-floor in one proof); the
    # finalize leg is finalize_windowed. Both are 5-public-input (window_root, seal, commitment, tip, K),
    # matching cardano_bound.inputs_bind_w. (Was: leap_windowed vk + a finalize_vk=vk PLACEHOLDER.)
    CER = os.path.join(HERE, "..", "circuit", "ceremony")
    vk = json.load(open(os.path.join(CER, "leap_bound_windowed_redeemer.json")))["vk"]
    finalize_vk = json.load(open(os.path.join(CER, "finalize_windowed_redeemer.json")))["vk"]

    # ACYCLIC ORDER (leap_ratelimit's own hash is a param to NOTHING - its cell is found by thread token - so
    # it derives LAST, and its ft_policy is the leap_mint_guard minting policy):
    # 1) minters (1 param each: genesis_ref) -> policy ids
    policy_nft       = apply_chain("chiral_policy_thread", "chiral_policy_thread", [C_oref(*GREF_A)], "cpt")
    ratelimit_thread = apply_chain("leap_ratelimit_thread", "leap_ratelimit_thread", [C_oref(*GREF_B)], "rlt")
    # 2) chiral_policy spend (needs policy_nft) -> policy_script
    policy_script    = apply_chain("chiral_policy", "chiral_policy", [C_bytes(policy_nft), C_bytes(POLICY_NAME)], "pol")
    # 3) cardano_bound (6 params incl vk/finalize_vk) - the leg verifier
    bound = apply_chain("cardano_bound", "cardano_bound",
                        [C_vk(vk), C_vk(finalize_vk), C_bytes(CHECKPOINT_NFT), C_bytes(policy_nft), C_bytes(POLICY_NAME), C_bytes(policy_script)], "bound")
    # 4) leap_mint_guard (the wrapped-FT minting policy) - needs bound + ratelimit_thread
    mint_guard = apply_chain("leap_mint_guard", "leap_mint_guard",
                             [C_bytes(FT_NAME), C_bytes(bound), C_bytes(policy_nft), C_bytes(POLICY_NAME), C_bytes(SEAL_REGISTRY_NFT), C_bytes(ratelimit_thread)], "mg")
    # 5) leap_ratelimit spend - LAST; its ft_policy == the leap_mint_guard policy id
    ratelimit_script = apply_chain("leap_ratelimit", "leap_ratelimit",
                                   [C_bytes(ratelimit_thread), C_bytes(mint_guard), C_bytes(FT_NAME), C_int(CAP), C_int(WINDOW_LEN)], "rl")

    manifest = {
        "_note": "DERIVATION DEMO - placeholders for gref_A/B, finalize_vk(=leap vk), checkpoint_nft, "
                 "seal_nullifier_hash. Swap real values at deploy; the acyclic order above is correct "
                 "(leap_ratelimit derives last, ft_policy=leap_mint_guard policy). GO-LIVE GATES: real "
                 "finalize_vk (run the finalize ceremony) + a funded deployer key + the deployed checkpoint "
                 "+ seal_nullifier, then submit the two genesis-mint txs (mint 1 thread token each, output "
                 "the datums below to chiral_policy_script / leap_ratelimit_script).",
        "params": {"policy_name": POLICY_NAME, "ft_name": FT_NAME, "K_genesis": K_DEFAULT,
                   "cap": CAP, "min_amount": MIN_AMOUNT, "max_amount": MAX_AMOUNT, "window_len": WINDOW_LEN,
                   "_caps_note": "SEC D6 reorg caps ENABLED (aggregate CAP compile-time/immutable; per-leap "
                                 "min/max in the governable PolicyState datum). Units: CKB shannons."},
        "policy_nft_minter": policy_nft,
        "ratelimit_thread_minter": ratelimit_thread,
        "chiral_policy_script": policy_script,
        "leap_ratelimit_script": ratelimit_script,
        "cardano_bound_script": bound,
        "leap_mint_guard_policy": mint_guard,
        "genesis_mint_datums": {
            "chiral_policy_cell": {"type": "PolicyState", "governor": "<deployer vkh>", "policy": {
                "paused_global": False, "paused_in": False, "paused_out": False, "min_amount": MIN_AMOUNT, "max_amount": MAX_AMOUNT, "min_confirmations": K_DEFAULT}},
            "leap_ratelimit_cell": {"type": "RateState", "window_start": 0, "minted_in_window": 0},
        },
    }
    print(json.dumps(manifest, indent=2))

if __name__ == "__main__":
    main()
