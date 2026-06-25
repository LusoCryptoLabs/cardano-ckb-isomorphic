#!/usr/bin/env python3
"""leap_mint.py - the LIVE value-bound leap: mint χCKB on Cardano against the ceremony Groth16 proof.

Phase A (--create): create a BoundState{ckb_seal=seal, state=#""} UTxO at the cardano_bound address.
Phase B (--leap [--live]): spend it via cardano_bound.Transition (verify the proof) WHILE leap_mint_guard
mints χCKB to Script(recipient), seal_nullifier inserts the seal (empty-tree -> present), and leap_ratelimit
ticks. Reference inputs: the live checkpoint + policy cells. Manual ExUnits (from the Aiken-measured costs).

Pre-req: validate_leap_binding.py must pass (seal/commitment bind the proof). Run --create, wait, then --leap.
"""
import os, sys, json, subprocess, time
from hashlib import blake2b
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, "..", "..", ".."))
sys.path.insert(0, HERE); sys.path.insert(0, os.path.join(ROOT, "cardano", "binding"))
import cbor2, pycardano as pc, cardano_net, d6_deploy as d6
from pycardano.serialization import ByteString   # chunks bytestrings > 64B into indefinite CBOR (proof.b = 96B)

PRE = os.path.join(ROOT, "deployed", "cardano", "preview")
M = json.load(open(os.path.join(PRE, "groth16-deploy.json")))
CKBC = json.load(open(os.path.join(PRE, "ckbcert-genesis.json")))
RED = json.load(open(os.path.join(HERE, "..", "circuit", "ceremony", "leap_bound_windowed_redeemer.json")))
VK = RED["vk"]; FIN_VK = json.load(open(os.path.join(HERE, "..", "circuit", "ceremony", "finalize_windowed_redeemer.json")))["vk"]

SEAL = bytes.fromhex("e86b1ceffa985264defbd099ce76af43c187c7ea5448eb919206094324314318")  # AC4 fresh lock @ height 21435552 (advanced-window leap)
AMOUNT = 20000000000
RECIPIENT = bytes.fromhex("2df44c71a4312463ba31315c5aa7725b6ad44cd544a055a3dde915a6")
NEW_STATE = AMOUNT.to_bytes(16, "little") + RECIPIENT
PI = [int(x) for x in RED["public_inputs_dec"]]
THREAD_NAME = bytes.fromhex("636b62636572742d746872656164")
FT_NAME = bytes.fromhex(d6.FT_NAME)            # cf87434b42
TN = pc.Network.TESTNET

def addr(h): return pc.Address(payment_part=pc.ScriptHash(bytes.fromhex(h)), network=TN)
def constr(i, fs): return cbor2.CBORTag(121 + i, fs)
FR_ORDER = 52435875175126190479447740508185965837690552500527637822603658699938581184513
def field_of_le(hexstr): return int.from_bytes(bytes.fromhex(hexstr), "little") % FR_ORDER

# ---- SMT: empty siblings + the new root after inserting `seal` ----
def h2(l, r): return blake2b(l + r, digest_size=32).digest()
DEPTH = 128                                     # SMT depth (low 128 bits of the 32B seal key); see g16/seal_set
def empty_sibs():
    e = bytes(32); out = []
    for _ in range(DEPTH): out.append(e); e = h2(e, e)
    return out                                  # [E0..E127] leaf-first
PRESENT = bytes([1]) * 32
def fold(value, key, sibs):
    cur = value
    for d in range(len(sibs)):
        bi = 255 - d
        bit = (key[bi // 8] >> (7 - bi % 8)) & 1
        cur = h2(sibs[d], cur) if bit == 1 else h2(cur, sibs[d])
    return cur
SIBS = empty_sibs()
NEW_ROOT = fold(PRESENT, SEAL, SIBS)
EMPTY_ROOT = fold(bytes(32), SEAL, SIBS)        # == seal_set.empty_root() (8a95af78…)

def compiled(label, n, name):
    bp = json.load(open(f"{d6.WORK}/{label}_{n}.json"))
    v = next(x for x in bp["validators"] if x["title"].startswith(name + ".") and (x["title"].endswith(".mint") or x["title"].endswith(".spend")))
    return pc.PlutusV3Script(bytes.fromhex(v["compiledCode"]))

def derive():
    subprocess.run([d6.AIKEN, "build"], cwd=HERE, check=True, capture_output=True)
    reg = d6.apply_chain("seal_nullifier", "seal_nullifier", [], "seal")
    d6.apply_chain("seal_thread", "seal_thread", [oref(M["seal_gref"]), d6.C_bytes(reg)], "sealt")
    pol_nft = d6.apply_chain("chiral_policy_thread", "chiral_policy_thread", [oref(M["policy_gref"])], "cpt")
    pol_script = d6.apply_chain("chiral_policy", "chiral_policy", [d6.C_bytes(pol_nft), d6.C_bytes(d6.POLICY_NAME)], "pol")
    rl_thread = d6.apply_chain("leap_ratelimit_thread", "leap_ratelimit_thread", [oref(M["ratelimit_gref"])], "rlt")
    bound = d6.apply_chain("cardano_bound", "cardano_bound",
                           [d6.C_vk(VK), d6.C_vk(FIN_VK), d6.C_bytes(M["checkpoint_nft"]), d6.C_bytes(pol_nft), d6.C_bytes(d6.POLICY_NAME), d6.C_bytes(pol_script)], "bound")
    mg = d6.apply_chain("leap_mint_guard", "leap_mint_guard",
                        [d6.C_bytes(d6.FT_NAME), d6.C_bytes(bound), d6.C_bytes(pol_nft), d6.C_bytes(d6.POLICY_NAME), d6.C_bytes(M["seal_registry_nft"]), d6.C_bytes(rl_thread)], "mg")
    d6.apply_chain("leap_ratelimit", "leap_ratelimit",
                   [d6.C_bytes(rl_thread), d6.C_bytes(mg), d6.C_bytes(d6.FT_NAME), d6.C_int(d6.CAP), d6.C_int(d6.WINDOW_LEN)], "rl")
    assert bound == M["cardano_bound_script"] and mg == M["leap_mint_guard_policy"], "derivation != manifest"
    return {"bound": compiled("bound", 6, "cardano_bound"), "mg": compiled("mg", 6, "leap_mint_guard"),
            "seal": compiled("seal", 0, "seal_nullifier"), "rl": compiled("rl", 5, "leap_ratelimit")}

def oref(s): t, i = s.split("#"); return d6.C_oref(t, int(i))
def find(ctx, address, policy, name=THREAD_NAME):
    for u in ctx.utxos(str(address)):
        ma = u.output.amount.multi_asset
        if ma and pc.ScriptHash(bytes.fromhex(policy)) in ma and pc.AssetName(name) in ma[pc.ScriptHash(bytes.fromhex(policy))]:
            return u
    return None

def main():
    ctx = cardano_net.chain_context(); sk, vk, a = cardano_net.account()
    bound_addr = addr(M["cardano_bound_script"])

    if "--create" in sys.argv:
        bs = pc.RawPlutusData(constr(0, [SEAL, b""]))            # BoundState{ckb_seal=seal, state=#""}
        b = pc.TransactionBuilder(ctx); b.add_input_address(a)
        b.add_output(pc.TransactionOutput(bound_addr, pc.Value(5_000_000), datum=bs))
        tx = b.build_and_sign([sk], change_address=a); txid = ctx.submit_tx(tx)
        print("BoundState created:", txid, "@", bound_addr)
        json.dump({"boundstate_tx": txid}, open(os.path.join(PRE, "leap-boundstate.json"), "w")); return

    # ---- reference scripts (so the leap tx fits the 16 KB size limit) ----
    S = derive()
    REFF = os.path.join(PRE, "leap-refscripts.json")
    names = ["bound", "seal", "rl", "mg"]
    if "--refscripts" in sys.argv:
        b = pc.TransactionBuilder(ctx); b.add_input_address(a)
        for nm in names:
            b.add_output(pc.TransactionOutput(a, pc.Value(60_000_000), script=S[nm]))
        tx = b.build_and_sign([sk], change_address=a); txid = ctx.submit_tx(tx)
        json.dump({nm: {"tx": txid, "ix": i} for i, nm in enumerate(names)}, open(REFF, "w"))
        print("ref scripts deployed:", txid, "(", ", ".join(f"{nm}=#{i}" for i, nm in enumerate(names)), ")"); return

    # ---- LEAP ----
    live = "--live" in sys.argv
    refs = json.load(open(REFF))
    refu = lambda nm: pc.UTxO(pc.TransactionInput(pc.TransactionId(bytes.fromhex(refs[nm]["tx"])), refs[nm]["ix"]),
                              pc.TransactionOutput(a, pc.Value(60_000_000), script=S[nm]))
    RB, RS, RR, RM = refu("bound"), refu("seal"), refu("rl"), refu("mg")
    # spent script UTxOs
    bound_in = find(ctx, bound_addr, M["leap_mint_guard_policy"]) or next((u for u in ctx.utxos(str(bound_addr))), None)
    reg_in = find(ctx, addr(M["seal_nullifier_script"]), M["seal_registry_nft"])
    rl_in = find(ctx, addr(M["leap_ratelimit_script"]), M["ratelimit_thread"])
    # reference cells
    ckpt_ref = find(ctx, addr(CKBC["advance_ckbcert_script"]), M["checkpoint_nft"])
    pol_ref = find(ctx, addr(M["policy_script"]), M["policy_nft"])
    print("bound_in:", bool(bound_in), "reg_in:", bool(reg_in), "rl_in:", bool(rl_in), "ckpt_ref:", bool(ckpt_ref), "pol_ref:", bool(pol_ref))
    assert all([bound_in, reg_in, rl_in, ckpt_ref, pol_ref]), "missing a cell"
    # GUARD: the leap proof's window_root (PI[0]) + tip (PI[3]) MUST bind the LIVE checkpoint datum that
    # cardano_bound reads (the ADVANCED cell, not the genesis pin), else inputs_bind_w fails on-chain.
    _d = ckpt_ref.output.datum
    _raw = _d.to_cbor() if hasattr(_d, "to_cbor") else (_d.cbor if hasattr(_d, "cbor") else bytes(_d))
    _cp = cbor2.loads(_raw).value                        # Checkpoint{chain_root, total_difficulty, window_root, tip_height}
    assert PI[0] == field_of_le(_cp[2].hex()), f"leap window_root != live checkpoint window_root; advance the checkpoint or regenerate the proof"
    assert PI[3] == int(_cp[3]), f"leap tip {PI[3]} != live checkpoint tip {int(_cp[3])}; advance to {PI[3]} or regenerate"
    print(f"[guard] leap binds the live checkpoint: window_root {_cp[2].hex()[:16]} tip {int(_cp[3])}")

    pr = RED["proof"]
    transition = pc.RawPlutusData(constr(0, [constr(0, [bytes.fromhex(pr["a"]), ByteString(bytes.fromhex(pr["b"])), bytes.fromhex(pr["c"])]), NEW_STATE, PI]))
    insert = pc.RawPlutusData(constr(0, [SEAL, SIBS]))
    tick = pc.RawPlutusData(constr(0, [AMOUNT]))
    leapin = pc.RawPlutusData(constr(0, []))

    lo = ctx.last_block_slot; hi = lo + 300
    # the rate-limiter reads `now` = the validity lower bound in POSIXTime MS (not the slot). preview:
    # POSIXTime_ms = (system_start_sec + slot) * 1000. The continuing RateState.window_start MUST equal it.
    SYSTEM_START = 1666656000
    now_ms = (SYSTEM_START + lo) * 1000
    seal_nft = pc.MultiAsset.from_primitive({bytes.fromhex(M["seal_registry_nft"]): {THREAD_NAME: 1}})
    rl_nft = pc.MultiAsset.from_primitive({bytes.fromhex(M["ratelimit_thread"]): {THREAD_NAME: 1}})
    ck_mint = pc.MultiAsset.from_primitive({bytes.fromhex(M["leap_mint_guard_policy"]): {FT_NAME: AMOUNT}})
    bs_out = pc.RawPlutusData(constr(0, [SEAL, NEW_STATE]))                 # continuing BoundState{seal, new_state}
    reg_out = pc.RawPlutusData(constr(0, [NEW_ROOT]))                       # SealSet{new_root}
    rate_out = pc.RawPlutusData(constr(0, [now_ms, AMOUNT]))                # RateState{window_start=now_ms, minted=amount}

    # SMT depth 128: the seal insert mem ~halves (fold ~6.5M + TxInfo ~2.6M ≈ 9M, vs ~15.6M at 256).
    EXU = {"bound": pc.ExecutionUnits(800_000, 3_400_000_000), "seal": pc.ExecutionUnits(10_800_000, 3_000_000_000),
           "rl": pc.ExecutionUnits(450_000, 200_000_000), "mg": pc.ExecutionUnits(1_700_000, 500_000_000)}
    b = pc.TransactionBuilder(ctx)
    b.add_input_address(a)
    b.add_script_input(bound_in, script=RB, redeemer=pc.Redeemer(transition, EXU["bound"]))
    b.add_script_input(reg_in, script=RS, redeemer=pc.Redeemer(insert, EXU["seal"]))
    b.add_script_input(rl_in, script=RR, redeemer=pc.Redeemer(tick, EXU["rl"]))
    b.reference_inputs.add(ckpt_ref); b.reference_inputs.add(pol_ref)
    b.mint = ck_mint
    b.add_minting_script(RM, pc.Redeemer(leapin, EXU["mg"]))
    b.add_output(pc.TransactionOutput(bound_addr, pc.Value(int(bound_in.output.amount.coin)), datum=bs_out))
    b.add_output(pc.TransactionOutput(addr(M["seal_nullifier_script"]), pc.Value(int(reg_in.output.amount.coin), seal_nft), datum=reg_out))
    b.add_output(pc.TransactionOutput(addr(M["leap_ratelimit_script"]), pc.Value(int(rl_in.output.amount.coin), rl_nft), datum=rate_out))
    b.add_output(pc.TransactionOutput(addr(RECIPIENT.hex()), pc.Value(1_500_000, ck_mint)))   # χCKB -> Script(recipient)
    b.validity_start = lo; b.ttl = hi
    pure = sorted([u for u in ctx.utxos(str(a)) if not u.output.amount.multi_asset], key=lambda u: int(u.output.amount.coin))
    b.collaterals = [pure[0]]
    b.required_signers = [vk.hash()]
    if not live:
        body = b.build(change_address=a)
        print("[dry] validity_start:", body.validity_start, "ttl:", body.ttl, "| now(lo):", lo)
        print("[dry] outputs:", len(body.outputs), "| mint:", b.mint)
        return
    tx = b.build_and_sign([sk], change_address=a)
    print("[live] tx validity_start:", tx.transaction_body.validity_start, "ttl:", tx.transaction_body.ttl)
    txid = ctx.submit_tx(tx)
    print("\nLEAP MINT submitted - preview tx:", txid, "| minted", AMOUNT, "χCKB -> Script", RECIPIENT.hex()[:12])
    json.dump({"leap_tx": txid, "amount": AMOUNT, "recipient": RECIPIENT.hex(), "seal": SEAL.hex()},
              open(os.path.join(PRE, "leap-mint.json"), "w"), indent=2)

if __name__ == "__main__":
    main()
