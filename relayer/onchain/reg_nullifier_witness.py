#!/usr/bin/env python3
"""reg_nullifier_witness.py <src_seal36_hex> [state_file] [old_root_hex] - emit a burn_nullifier_registry
insert witness for the NEXT nullifier, against a registry SMT that may already hold keys (repeatable leaps).

The nullifier key is derived exactly as bound_asset_v2::seal_nullifier_inserts:
  key = blake2b-256( 0x03 ‖ src_txid(32) ‖ src_idx(4 LE) ) = blake2b-256(0x03 ‖ src_seal36)
  [NO personalization; 0x03 = χCKB-leap leg domain tag, disjoint from the 0x01 χADA-mint and 0x02 CKB-release
   legs that share this registry]

The on-chain set is a 256-deep SPARSE MERKLE TREE (burn_nullifier_registry.rs):
  h2(l,r) = blake2b-256(l‖r, personal="ckb-smt-null-set");  leaf value PRESENT=0x01*32, absent=0x00*32.
This builds the REAL 256 siblings on the new key's path against the CURRENT present-key set (read from
state_file = {root, keys[]}; absent/empty -> the genesis-empty tree), so:
  fold(ABSENT, key, sib) == old_root  (non-membership)   and   fold(PRESENT, key, sib) == new_root.
For the empty set every sibling is the empty-subtree level e[d] (the original genesis case) - this code
reduces to that exactly. Prints JSON {key, witness, new_root, old_root, n_keys}. Pure (does NOT write state;
the caller persists key+new_root only after the tx confirms)."""
import sys, os, json, hashlib

ZERO = b"\x00" * 32
PRESENT = b"\x01" * 32
PERSON = b"ckb-smt-null-set"

def h2(l, r):
    return hashlib.blake2b(l + r, digest_size=32, person=PERSON).digest()

# e[h] = hash of an all-empty subtree of height h (e[0] = empty leaf value = ZERO).
def empty_levels():
    e = [ZERO]
    for _ in range(256):
        e.append(h2(e[-1], e[-1]))
    return e  # len 257: e[0..256]
E = empty_levels()

def bit(key, bi):                                  # bit index bi: MSB-of-byte-0 first (matches the verifier)
    return (key[bi // 8] >> (7 - (bi % 8))) & 1

def subtree(h, keys):
    """Hash of the height-h subtree containing exactly `keys` (each a full 256-bit key routed here)."""
    if not keys:
        return E[h]
    if h == 0:
        return PRESENT                              # one present key occupies this leaf
    bi = 256 - h                                    # split bit at this level (fold d = h-1 -> bit 255-d = 256-h)
    left = [k for k in keys if bit(k, bi) == 0]
    right = [k for k in keys if bit(k, bi) == 1]
    return h2(subtree(h - 1, left), subtree(h - 1, right))

def siblings(present, K):
    """256 siblings (fold order, leaf-level first) on K's path through the tree over `present` (K absent)."""
    sib = [None] * 256
    cur = list(present)
    for h in range(256, 0, -1):                     # root (h=256) down to leaf split (h=1)
        bi = 256 - h
        same, other = [], []
        for k in cur:
            (same if bit(k, bi) == bit(K, bi) else other).append(k)
        sib[h - 1] = subtree(h - 1, other)          # sibling = opposite-branch subtree of height h-1
        cur = same
    return sib

def fold(value, key, sib):
    cur = value
    for d in range(256):
        b = bit(key, 255 - d)
        cur = h2(sib[d], cur) if b == 1 else h2(cur, sib[d])
    return cur

def main():
    seal36 = bytes.fromhex(sys.argv[1].removeprefix("0x"))
    if len(seal36) != 36:
        raise SystemExit("src_seal36 must be 36 bytes = txid(32) ‖ idx(4 LE)")
    state_file = sys.argv[2] if len(sys.argv) > 2 else None
    keys = []
    if state_file and os.path.exists(state_file):
        keys = [bytes.fromhex(k.removeprefix("0x")) for k in json.load(open(state_file)).get("keys", [])]
    # #7 leg domain tag. DEFAULT empty = UNtagged, matching the CURRENTLY-DEPLOYED pre-#7 bound_asset_v2
    # (0x4cc7ae86). The #7 redeploy ships the tagged contract -> set CHIRAL_NULL_TAG=03.
    _tag = bytes.fromhex(os.environ.get("CHIRAL_NULL_TAG", ""))
    key = hashlib.blake2b(_tag + seal36, digest_size=32).digest()   # == bound_asset_v2 b2b256(&[&[tag],txid,idx])
    if key in keys:
        raise SystemExit(f"nullifier {key.hex()} already inserted - this seal outpoint was already leaped (replay)")

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
