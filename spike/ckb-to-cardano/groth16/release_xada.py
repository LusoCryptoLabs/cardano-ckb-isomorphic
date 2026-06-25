#!/usr/bin/env python3
"""release_xada.py - the χADA RETURN release: spend the ada_escrow UTxO via Action::Release, verifying the
Groth16 burn proof, nullifying the burn seal once in the seal registry, and PAYING the locked ADA to the burn's
bound Cardano recipient. The mirror of leap_mint.py's proof-gated spend, for the return leg.

  python3 release_xada.py --refscripts        # one-time: deploy ada_escrow + seal_nullifier as reference scripts
  python3 release_xada.py [--live]            # build (and submit) the Release tx

env: CHIRAL_RETURN_VK (burn redeemer json), CHIRAL_CHECKPOINT_NFT (re-anchored nft), CHIRAL_BURN_REDEEMER,
     CHIRAL_ESCROW_TX (escrow utxo txid), CHIRAL_PREVIEW_KEY.
"""
import os, sys, json, subprocess
from hashlib import blake2b
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, "..", "..", ".."))
sys.path.insert(0, HERE); sys.path.insert(0, os.path.join(ROOT, "cardano", "binding"))
import cbor2, pycardano as pc, cardano_net, d6_deploy as d6
from pycardano.serialization import ByteString

PRE = os.path.join(ROOT, "deployed", "cardano", "preview")
M = json.load(open(os.path.join(PRE, "groth16-deploy.json")))
CKBC = json.load(open(os.path.join(PRE, "ckbcert-genesis.json")))
ESC = json.load(open(os.path.join(PRE, os.environ.get("CHIRAL_ESCROW_IN", "xada-escrow.json"))))   # return escrow (decoupled from the static forward config)
RED = json.load(open(os.environ["CHIRAL_RETURN_VK"]))          # the BURN redeemer (vk + proof + public_inputs)
VK = RED["vk"]
CHECKPOINT_NFT = os.environ.get("CHIRAL_CHECKPOINT_NFT", M["checkpoint_nft"])

# the bound burn facts (must match what the circuit proved + the escrow datum).
BURN_SEAL = bytes.fromhex(os.environ.get("CHIRAL_BURN_SEAL", "6a19638a6910a0daac120873d5974ae5542089825f789295de429cf5ccbb63cd"))
CARDANO_RECIPIENT = bytes.fromhex(ESC["ckb_recipient"])[:28]    # 28-byte payment cred the Release pays
AMOUNT = int(ESC["amount"])                                    # == esc.amount the Release pays
PI = [int(x) for x in RED["public_inputs_dec"]]
THREAD_NAME = bytes.fromhex("636b62636572742d746872656164")
TN = pc.Network.TESTNET

def addr(h): return pc.Address(payment_part=pc.ScriptHash(bytes.fromhex(h)), network=TN)
def constr(i, fs): return cbor2.CBORTag(121 + i, fs)
def oref(s): t, i = s.split("#"); return d6.C_oref(t, int(i))

# ---- SMT (seal_set, depth 128, leaf-first fold): REAL siblings of the new seal's path in the tree of the
# already-inserted seals - so REPEATED returns work (the empty-tree shortcut only served the first return).
ZERO = bytes(32); PRESENT = bytes([1]) * 32
def h2(l, r): return blake2b(l + r, digest_size=32).digest()
E = [ZERO]
for _ in range(129): E.append(h2(E[-1], E[-1]))            # empty subtree roots by height
def bitv(k, bi): return (k[bi // 8] >> (7 - bi % 8)) & 1
def merkle_root(keys, level):                              # level 0 = root (bit 128) … 128 = leaf (bit 255 last)
    if level == 128: return PRESENT if keys else ZERO
    if not keys: return E[128 - level]
    bit = 128 + level
    z = [k for k in keys if bitv(k, bit) == 0]; o = [k for k in keys if bitv(k, bit) == 1]
    return h2(merkle_root(z, level + 1), merkle_root(o, level + 1))
def smt_siblings(present, K):                              # siblings of K's path in the {present} tree (leaf-first)
    sib = [None] * 128; cur = list(present)
    for L in range(128):
        bit = 128 + L; kb = bitv(K, bit)
        sib[127 - L] = merkle_root([k for k in cur if bitv(k, bit) != kb], L + 1)
        cur = [k for k in cur if bitv(k, bit) == kb]
    return sib
def fold(value, key, sibs):                               # mirror of the on-chain seal_set verification
    cur = value
    for d in range(128):
        bi = 255 - d
        cur = h2(sibs[d], cur) if bitv(key, bi) == 1 else h2(cur, sibs[d])
    return cur
# off-chain mirror of the on-chain seal_set: the seals already nullified (so siblings reflect the real tree).
SEAL_STATE = os.path.join(HERE, "..", "..", "..", "relayer", "onchain", "xada_seal_state.json")
PRESENT_SEALS = [bytes.fromhex(s) for s in (json.load(open(SEAL_STATE)).get("seals", []) if os.path.exists(SEAL_STATE) else [])]
SIBS = smt_siblings(PRESENT_SEALS, BURN_SEAL)
NEW_ROOT = fold(PRESENT, BURN_SEAL, SIBS)
OLD_ROOT = fold(ZERO, BURN_SEAL, SIBS)

def compiled(label, n, name):
    bp = json.load(open(f"{d6.WORK}/{label}_{n}.json"))
    v = next(x for x in bp["validators"] if x["title"].startswith(name + ".") and (x["title"].endswith(".mint") or x["title"].endswith(".spend")))
    return pc.PlutusV3Script(bytes.fromhex(v["compiledCode"]))

def derive():
    subprocess.run([d6.AIKEN, "build"], cwd=HERE, check=True, capture_output=True)
    esc = d6.apply_chain("ada_escrow", "ada_escrow",
                         [d6.C_vk(VK), d6.C_bytes(CHECKPOINT_NFT), d6.C_bytes(M["seal_registry_nft"]),
                          d6.C_bytes(M["policy_nft"]), d6.C_bytes(d6.POLICY_NAME), d6.C_bytes(M["policy_script"])], "esc")
    d6.apply_chain("seal_nullifier", "seal_nullifier", [], "seal")
    return {"esc_hash": esc, "esc": compiled("esc", 6, "ada_escrow"), "seal": compiled("seal", 0, "seal_nullifier")}

def find(ctx, address, policy, name=THREAD_NAME):
    for u in ctx.utxos(str(address)):
        ma = u.output.amount.multi_asset
        if ma and pc.ScriptHash(bytes.fromhex(policy)) in ma and pc.AssetName(name) in ma[pc.ScriptHash(bytes.fromhex(policy))]:
            return u
    return None

def main():
    ctx = cardano_net.chain_context(); sk, vk, a = cardano_net.account()
    S = derive()
    esc_addr = addr(S["esc_hash"])
    print("ada_escrow (return, burn-vk) addr:", esc_addr, "| script", S["esc_hash"])
    REFF = os.path.join(PRE, "xada-release-refscripts.json")

    if "--refscripts" in sys.argv:
        b = pc.TransactionBuilder(ctx); b.add_input_address(a)
        b.add_output(pc.TransactionOutput(a, pc.Value(120_000_000), script=S["esc"]))
        b.add_output(pc.TransactionOutput(a, pc.Value(70_000_000), script=S["seal"]))
        tx = b.build_and_sign([sk], change_address=a); txid = ctx.submit_tx(tx)
        json.dump({"esc": {"tx": txid, "ix": 0}, "seal": {"tx": txid, "ix": 1}}, open(REFF, "w"))
        print("ref scripts deployed:", txid, "(esc=#0, seal=#1)"); return

    if "--check-refs" in sys.argv:
        # read-only poll: are the deployed reference-script UTxOs live yet? exit 0 if both present, else 1.
        # Lets the orchestrator poll for confirmation instead of a blind fixed sleep before Release spends them.
        try:
            refs = json.load(open(REFF))
        except Exception:
            print("refs file missing"); sys.exit(1)
        live_ins = {(str(u.input.transaction_id), u.input.index) for u in ctx.utxos(str(a))}
        ok = (refs["esc"]["tx"], refs["esc"]["ix"]) in live_ins and (refs["seal"]["tx"], refs["seal"]["ix"]) in live_ins
        print("refs live:", ok, "tx", refs["esc"]["tx"][:12]); sys.exit(0 if ok else 1)

    live = "--live" in sys.argv
    refs = json.load(open(REFF))
    refu = lambda nm, sc, val: pc.UTxO(pc.TransactionInput(pc.TransactionId(bytes.fromhex(refs[nm]["tx"])), refs[nm]["ix"]),
                                       pc.TransactionOutput(a, pc.Value(val), script=sc))
    R_ESC = refu("esc", S["esc"], 120_000_000); R_SEAL = refu("seal", S["seal"], 70_000_000)

    # the cells: escrow UTxO (locked), the seal registry (empty), checkpoint + policy reference cells.
    esc_txid = os.environ.get("CHIRAL_ESCROW_TX", ESC["escrow_tx"])
    esc_in = next((u for u in ctx.utxos(str(esc_addr)) if str(u.input.transaction_id) == esc_txid), None) \
             or next((u for u in ctx.utxos(str(esc_addr))), None)
    reg_in = find(ctx, addr(M["seal_nullifier_script"]), M["seal_registry_nft"])
    # the checkpoint reference cell carries CHECKPOINT_NFT; ada_escrow finds it by NFT (any address). Off-chain
    # we filter by address: the advance_ckbcert lineage by default, or the STABLE ckpt_registry script (E2) when
    # CHIRAL_CKPT_SCRIPT is set (the registry cell lives at ckpt_registry's address, not advance_ckbcert's).
    ckpt_ref = find(ctx, addr(os.environ.get("CHIRAL_CKPT_SCRIPT", CKBC["advance_ckbcert_script"])), CHECKPOINT_NFT)
    pol_ref = find(ctx, addr(M["policy_script"]), M["policy_nft"])
    print("esc_in:", bool(esc_in), "reg_in:", bool(reg_in), "ckpt_ref:", bool(ckpt_ref), "pol_ref:", bool(pol_ref))
    assert all([esc_in, reg_in, ckpt_ref, pol_ref]), "missing a cell"
    # GUARD: the proof's window_root (PI[0]) + tip (PI[3]) must bind the live checkpoint datum.
    _raw = ckpt_ref.output.datum.to_cbor() if hasattr(ckpt_ref.output.datum, "to_cbor") else bytes(ckpt_ref.output.datum)
    _cp = cbor2.loads(_raw).value
    FR = 52435875175126190479447740508185965837690552500527637822603658699938581184513
    assert PI[0] == int.from_bytes(_cp[2], "little") % FR, "proof window_root != checkpoint window_root"
    assert PI[3] == int(_cp[3]), f"proof tip {PI[3]} != checkpoint tip {int(_cp[3])}"
    # the computed old-root (from our seal-state mirror) MUST equal the live registry root, else the SMT insert
    # witness is stale; if this trips, the seal-state is out of sync with the on-chain seal_set.
    _rr = reg_in.output.datum.to_cbor() if hasattr(reg_in.output.datum, "to_cbor") else bytes(reg_in.output.datum)
    assert cbor2.loads(_rr).value[0] == OLD_ROOT, f"seal-state out of sync: computed old_root {OLD_ROOT.hex()[:16]} != live {cbor2.loads(_rr).value[0].hex()[:16]}"
    print(f"[guard] proof binds live checkpoint window_root {_cp[2].hex()[:16]} tip {int(_cp[3])}; {len(PRESENT_SEALS)} seal(s) tracked")

    pr = RED["proof"]
    proof = constr(0, [bytes.fromhex(pr["a"]), ByteString(bytes.fromhex(pr["b"])), bytes.fromhex(pr["c"])])
    release = pc.RawPlutusData(constr(0, [proof, CARDANO_RECIPIENT, BURN_SEAL, PI]))   # Action::Release
    insert = pc.RawPlutusData(constr(0, [BURN_SEAL, SIBS]))                            # seal_nullifier Insert
    reg_out = pc.RawPlutusData(constr(0, [NEW_ROOT]))                                  # SealSet{new_root}
    seal_nft = pc.MultiAsset.from_primitive({bytes.fromhex(M["seal_registry_nft"]): {THREAD_NAME: 1}})
    recip_addr = pc.Address(payment_part=pc.VerificationKeyHash(CARDANO_RECIPIENT), network=TN)  # pays() matches the cred hash

    # esc does a Groth16 verify PLUS inputs_bind + seal_consumed + pays over the full TxInfo - heavier than the
    # bare verify in leap_mint (800k/3.4B). 900k/3.6B underbudgets the steps -> FailedUnexpectedly on-chain.
    # Budget generously but within the per-tx limits (mem 13M < 16.5M, steps 9.1B < 10B with the seal's 11M/3.1B).
    EXU = {"esc": pc.ExecutionUnits(2_000_000, 6_000_000_000), "seal": pc.ExecutionUnits(11_000_000, 3_100_000_000)}
    b = pc.TransactionBuilder(ctx)
    b.add_input_address(a)
    b.add_script_input(esc_in, script=R_ESC, redeemer=pc.Redeemer(release, EXU["esc"]))
    b.add_script_input(reg_in, script=R_SEAL, redeemer=pc.Redeemer(insert, EXU["seal"]))
    b.reference_inputs.add(ckpt_ref); b.reference_inputs.add(pol_ref)
    b.add_output(pc.TransactionOutput(recip_addr, pc.Value(AMOUNT)))                                  # release ADA -> recipient
    b.add_output(pc.TransactionOutput(addr(M["seal_nullifier_script"]), pc.Value(int(reg_in.output.amount.coin), seal_nft), datum=reg_out))
    pure = sorted([u for u in ctx.utxos(str(a)) if not u.output.amount.multi_asset and int(u.output.amount.coin) >= 5_000_000], key=lambda u: int(u.output.amount.coin))
    # pick a random collateral among the SMALLEST few eligible pure cells (not always pure[0]) so a concurrent
    # Cardano-key tx rarely grabs the SAME collateral UTxO -> fewer "inputs spent" self-collisions. All eligible
    # cells are valid collateral; staying in the small tail keeps the reserved-but-returned collateral modest.
    import random
    b.collaterals = [random.choice(pure[:min(len(pure), 5)])]
    b.required_signers = [vk.hash()]
    if not live:
        body = b.build(change_address=a)
        print("[dry] outputs:", len(body.outputs), "| release", AMOUNT, "-> recip", CARDANO_RECIPIENT.hex()[:12], "| new seal root", NEW_ROOT.hex()[:12]); return
    tx = b.build_and_sign([sk], change_address=a); txid = ctx.submit_tx(tx)
    print("\nχADA RELEASE submitted - preview tx:", txid, "| released", AMOUNT, "lovelace ->", CARDANO_RECIPIENT.hex()[:12])
    json.dump({"release_tx": txid, "amount": AMOUNT, "recipient": CARDANO_RECIPIENT.hex(), "burn_seal": BURN_SEAL.hex(),
               "escrow_tx": esc_txid}, open(os.path.join(PRE, "xada-release.json"), "w"), indent=2)
    # record the nullified seal so the next return computes correct siblings against the grown tree.
    seals = json.load(open(SEAL_STATE)).get("seals", []) if os.path.exists(SEAL_STATE) else []
    if BURN_SEAL.hex() not in seals: seals.append(BURN_SEAL.hex())
    json.dump({"seals": seals, "root": NEW_ROOT.hex()}, open(SEAL_STATE, "w"), indent=2)

if __name__ == "__main__":
    main()
