#!/usr/bin/env python3
"""xada_reg_witness.py <material_hex> [state_file] [old_root_hex] - emit a burn_nullifier_registry insert
witness for the χADA mint. Identical SMT to reg_nullifier_witness.py, but the nullifier key is derived as
`xada_mint.rs` derives it:  key = blake2b-256( 0x01 ‖ escrow_tx_body )  [NO personalization; 0x01 = χADA-mint
leg domain tag, disjoint from the 0x02 CKB-release and 0x03 χCKB-leap legs sharing this registry].
(reg_nullifier_witness.py keys on a fixed 36-byte seal; here the material is the whole certified Cardano
escrow tx body, any length - so this is a thin variant without the 36-byte length check.)

256-deep sparse Merkle tree (burn_nullifier_registry.rs): h2(l,r)=blake2b-256(l‖r, person="ckb-smt-null-set");
PRESENT=0x01*32, absent=0x00*32. Builds the REAL 256 siblings on the new key's path against the CURRENT
present-key set (state_file = {root, keys[]}; empty -> genesis tree) so fold(ABSENT,..)==old_root and
fold(PRESENT,..)==new_root. Prints {key, witness, old_root, new_root, n_keys}. Pure (caller persists state)."""
import sys, os, json, hashlib

ZERO = b"\x00" * 32
PRESENT = b"\x01" * 32
PERSON = b"ckb-smt-null-set"

def h2(l, r):
    return hashlib.blake2b(l + r, digest_size=32, person=PERSON).digest()

def empty_levels():
    e = [ZERO]
    for _ in range(256):
        e.append(h2(e[-1], e[-1]))
    return e
E = empty_levels()

def bit(key, bi):
    return (key[bi // 8] >> (7 - (bi % 8))) & 1

def subtree(h, keys):
    if not keys:
        return E[h]
    if h == 0:
        return PRESENT
    bi = 256 - h
    left = [k for k in keys if bit(k, bi) == 0]
    right = [k for k in keys if bit(k, bi) == 1]
    return h2(subtree(h - 1, left), subtree(h - 1, right))

def siblings(present, K):
    sib = [None] * 256
    cur = list(present)
    for h in range(256, 0, -1):
        bi = 256 - h
        same, other = [], []
        for k in cur:
            (same if bit(k, bi) == bit(K, bi) else other).append(k)
        sib[h - 1] = subtree(h - 1, other)
        cur = same
    return sib

def fold(value, key, sib):
    cur = value
    for d in range(256):
        b = bit(key, 255 - d)
        cur = h2(sib[d], cur) if b == 1 else h2(cur, sib[d])
    return cur

def main():
    material = bytes.fromhex(sys.argv[1].removeprefix("0x"))
    # #7 leg domain tag. DEFAULT empty = UNtagged, matching the CURRENTLY-DEPLOYED pre-#7 owner lock
    # (0xd409ffcf) / xada_mint (0x92e94035). The #7 redeploy ships the tagged contract -> set CHIRAL_NULL_TAG=01.
    _tag = bytes.fromhex(os.environ.get("CHIRAL_NULL_TAG", ""))
    key = hashlib.blake2b(_tag + material, digest_size=32).digest()   # == xada_mint b2b256(&[&[tag],&tx_body])
    state_file = sys.argv[2] if len(sys.argv) > 2 else None
    keys = []
    if state_file and os.path.exists(state_file):
        keys = [bytes.fromhex(k.removeprefix("0x")) for k in json.load(open(state_file)).get("keys", [])]
    if key in keys:
        raise SystemExit(f"nullifier {key.hex()} already inserted - this escrow tx was already minted (replay)")
    old_root = subtree(256, keys)
    if len(sys.argv) > 3:
        want = bytes.fromhex(sys.argv[3].removeprefix("0x"))
        if want != old_root:
            raise SystemExit(f"computed root {old_root.hex()} != live registry root {want.hex()} (state out of sync)")
    sib = siblings(keys, key)
    assert fold(ZERO, key, sib) == old_root, "non-membership self-check failed"
    new_root = fold(PRESENT, key, sib)
    assert subtree(256, keys + [key]) == new_root, "insert self-check failed"
    witness = key + b"".join(sib)
    print(json.dumps({"key": "0x" + key.hex(), "witness": "0x" + witness.hex(),
                      "old_root": "0x" + old_root.hex(), "new_root": "0x" + new_root.hex(), "n_keys": len(keys)}))

if __name__ == "__main__":
    main()
