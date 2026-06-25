#!/usr/bin/env python3
"""escrow_lock.py - χADA leg P4c: LOCK real preview ADA at the `ada_escrow` address with an inline EscrowDatum.

This is the Cardano side of the forward leg (spike/cardano-to-ckb-zk/XADA_LEG.md): a user locks lovelace at
the escrow; that certified output is what the live `xada_mint` CKB type script reads (Mithril-proven) to mint
χADA on CKB. Mirrors leap_mint.py --create (same pycardano submit), but the datum is the EscrowDatum and the
address is `ada_escrow` applied with the deployed params.

NOTE (forward demo): the `ada_escrow` RELEASE path verifies a Groth16 proof of a CKB χADA-burn - that burn
circuit is P5, so we apply a PLACEHOLDER return-vk here (the leap vk). The forward leg never runs release, so
the escrow address is valid for the mint demo; P5 redeploys with the real burn-vk for the actual return trip.
That is why we lock a SMALL amount (5 ADA).

Run:  python3 escrow_lock.py            # dry: derive + print the escrow address + datum
      python3 escrow_lock.py --live     # build + submit the lock tx on preview
"""
import os, sys, json
from hashlib import blake2b
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, "..", "..", ".."))
sys.path.insert(0, HERE); sys.path.insert(0, os.path.join(ROOT, "cardano", "binding"))
import cbor2, pycardano as pc, cardano_net, d6_deploy as d6

PRE = os.path.join(ROOT, "deployed", "cardano", "preview")
M = json.load(open(os.path.join(PRE, "groth16-deploy.json")))
# the ada_escrow Release reads the CKB-header checkpoint by this NFT; CHIRAL_CHECKPOINT_NFT re-points it at a
# RE-ANCHORED checkpoint (the return proof binds that window_root/tip_height). Default = the forward deploy's.
if os.environ.get("CHIRAL_CHECKPOINT_NFT"):
    M["checkpoint_nft"] = os.environ["CHIRAL_CHECKPOINT_NFT"]
RED = json.load(open(os.path.join(HERE, "..", "circuit", "ceremony", "leap_bound_windowed_redeemer.json")))
LEAP_VK = RED["vk"]   # the forward leap vk
# P5: the REAL return (burn) vk from the burn-instance ceremony. Set CHIRAL_RETURN_VK to xada_burn_redeemer.json
# to deploy the SOUND, non-drainable escrow - the Release path then verifies a real χADA-burn proof against it.
_rv = os.environ.get("CHIRAL_RETURN_VK")
VK = json.load(open(_rv))["vk"] if _rv else LEAP_VK   # placeholder leap vk only if no real burn-vk supplied
# SEC (audit #4): while VK is the leap PLACEHOLDER, the escrow's Release path verifies a vk whose proving key +
# prover are ON DISK (circuit/ceremony/) - so a self-bound leap proof can drain the escrow with NO real χADA
# burn. Until P5 deploys the real burn-vk, refuse to lock more than a trivial demo amount at this address.
DEMO_MAX = 5_000_000  # lovelace (5 ADA) - the most that may be locked at a placeholder-vk escrow

# χADA recipient on CKB = the CKB lock HASH where xada_mint mints χADA (32 bytes). Default: the relayer's own
# lock (the original self-mint demo). SELF-SERVE: the dapp passes the USER's CKB lock hash via env so the
# minted χADA is owned by the user - the owner lock enforces output.lock_hash == this recipient in-VM.
CKB_RECIPIENT = bytes.fromhex(os.environ.get("CHIRAL_XADA_RECIPIENT",
    "7a971a3b730d3e5b69f73ac7add6dcd2396cab9523176132ed23e17500c820c7"))
AMOUNT = int(os.environ.get("CHIRAL_XADA_AMOUNT", "3000000"))   # lovelace -> mints AMOUNT χADA 1:1
NONCE  = int(os.environ.get("CHIRAL_XADA_NONCE",  "4"))         # fresh nonce -> a distinct tx -> a fresh registry key
TN = pc.Network.TESTNET

def constr(i, fs): return cbor2.CBORTag(121 + i, fs)

def derive_escrow():
    import subprocess
    subprocess.run([d6.AIKEN, "build"], cwd=HERE, check=True, capture_output=True)
    # ada_escrow(vk, checkpoint_nft, seal_registry_nft, policy_nft, policy_name, policy_script)
    h = d6.apply_chain("ada_escrow", "ada_escrow",
                       [d6.C_vk(VK), d6.C_bytes(M["checkpoint_nft"]), d6.C_bytes(M["seal_registry_nft"]),
                        d6.C_bytes(M["policy_nft"]), d6.C_bytes(d6.POLICY_NAME), d6.C_bytes(M["policy_script"])], "esc")
    return h

def main():
    escrow_hash = derive_escrow()
    escrow_addr = pc.Address(payment_part=pc.ScriptHash(bytes.fromhex(escrow_hash)), network=TN)
    addr_hex = escrow_addr.to_primitive().hex()    # the EXACT address bytes xada_mint must bake as escrow_addr
    # The DEPLOYED xada_mint_owner bakes the escrow address it will accept. If ada_escrow.ak has changed since
    # that deploy (e.g. the audit #8 K_MIN edit changed its hash), the freshly-derived address won't match - so
    # lock at the address the owner lock actually expects, to keep the SAME χADA token id (= owner lock hash).
    try:
        _owner = json.load(open(os.path.join(ROOT, "relayer", "onchain", "xada_owner_deploy.json")))
        _expected = _owner.get("escrowAddr")
        # CHIRAL_ESCROW_NO_OVERRIDE=1: lock at the FRESHLY-DERIVED address (e.g. the sound burn-vk RETURN escrow,
        # whose hash legitimately differs from the forward owner-lock-expected one) instead of forcing the old addr.
        if _expected and _expected != addr_hex and not os.environ.get("CHIRAL_ESCROW_NO_OVERRIDE"):
            print(f"NOTE: derived escrow {addr_hex} != owner-lock-expected {_expected}; locking at the expected addr "
                  f"(ada_escrow.ak changed since deploy). Same token id preserved.")
            addr_hex = _expected
            escrow_addr = pc.Address(payment_part=pc.ScriptHash(bytes.fromhex(_expected[2:])), network=TN)  # drop 0x70 header
    except Exception as _e:
        print("WARN: could not read owner-lock escrowAddr:", _e)
    datum = pc.RawPlutusData(constr(0, [CKB_RECIPIENT, AMOUNT, NONCE]))   # EscrowDatum{ckb_recipient, amount, nonce}
    print("ada_escrow script hash :", escrow_hash)
    print("ada_escrow address     :", escrow_addr)
    print("ada_escrow addr bytes  :", addr_hex, "  <- bake as xada_mint escrow_addr")
    print("EscrowDatum            : ckb_recipient", CKB_RECIPIENT.hex(), "amount", AMOUNT, "nonce", NONCE)

    placeholder = VK == LEAP_VK
    if placeholder:
        print(f"\n[audit #4] WARNING: return-vk is the PLACEHOLDER leap vk - this escrow is DRAINABLE "
              f"(its proving key is on disk). Safe to fund at most {DEMO_MAX/1_000_000} ADA here until P5.")

    if "--live" not in sys.argv:
        print("\nDRY. Pass --live to lock", AMOUNT/1_000_000, "ADA at the escrow.")
        return

    # SEC (audit #4): refuse to fund a drainable placeholder-vk escrow with non-trivial value.
    if placeholder and AMOUNT > DEMO_MAX and os.environ.get("CHIRAL_ESCROW_FORCE") != "1":
        sys.exit(f"REFUSING: escrow return-vk is the PLACEHOLDER leap vk (proving key on disk -> the Release "
                 f"path is satisfiable with NO real burn, i.e. drainable). AMOUNT={AMOUNT} lovelace > "
                 f"DEMO_MAX={DEMO_MAX}. Deploy the real burn-vk (P5) before funding, or set CHIRAL_ESCROW_FORCE=1 "
                 f"to acknowledge this is a throwaway demo lock.")

    ctx = cardano_net.chain_context(); sk, vk, a = cardano_net.account()
    b = pc.TransactionBuilder(ctx); b.add_input_address(a)
    b.add_output(pc.TransactionOutput(escrow_addr, pc.Value(AMOUNT), datum=datum))
    tx = b.build_and_sign([sk], change_address=a); txid = ctx.submit_tx(tx)
    state = {
        "escrow_tx": txid, "escrow_index": 0,
        "escrow_script_hash": escrow_hash, "escrow_address": str(escrow_addr), "escrow_addr_hex": addr_hex,
        "ckb_recipient": CKB_RECIPIENT.hex(), "amount": AMOUNT, "nonce": NONCE,
        "note": "forward-demo escrow; return-vk is a PLACEHOLDER (P5 redeploys). xada_mint args escrow_addr = escrow_addr_hex.",
    }
    # CHIRAL_ESCROW_OUT: write the RETURN escrow (orchestrator) to a SEPARATE file so it never clobbers the
    # static FORWARD escrow config (deployed/cardano/preview/xada-escrow.json) the dapp serves to testers.
    esc_out = os.path.join(PRE, os.environ.get("CHIRAL_ESCROW_OUT", "xada-escrow.json"))
    json.dump(state, open(esc_out, "w"), indent=2)
    print("\nLOCKED", AMOUNT/1_000_000, "ADA at escrow:", txid, "@", escrow_addr)
    print("wrote", esc_out)

if __name__ == "__main__":
    main()
