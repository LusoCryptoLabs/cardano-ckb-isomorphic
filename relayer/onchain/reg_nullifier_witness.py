#!/usr/bin/env python3
"""reg_nullifier_witness.py <src_seal36_hex> [old_root_hex] — emit the burn_nullifier_registry insert
witness for a FIRST insert into the EMPTY genesis SMT (the leap nullifier set's genesis singleton).

The nullifier key is derived exactly as bound_asset_v2::seal_nullifier_inserts:
  key = blake2b-256( src_txid(32) ‖ src_idx(4 LE) ) = blake2b-256(src_seal36)   [PLAIN blake2b, NO personal]

Mirrors burn_nullifier_registry.rs for the path: a 256-deep sparse Merkle tree with
  h2(l,r) = blake2b-256(l‖r, personal="ckb-smt-null-set"),  leaf "present" value = 0x01*32.
For the empty tree every sibling on any key's path is the empty-subtree level e[d], so the witness is
  key(32) ‖ e[0] ‖ e[1] ‖ … ‖ e[255]   (256 siblings, leaf-level first)
and the new root = fold(PRESENT, key, e). Prints JSON {key, witness, new_root, empty_root}. If old_root_hex
is given, asserts it equals empty_root (this helper only handles the genesis-empty insert)."""
import sys, json, hashlib

ZERO = b"\x00" * 32
PRESENT = b"\x01" * 32
PERSON = b"ckb-smt-null-set"

def h2(l, r):
    return hashlib.blake2b(l + r, digest_size=32, person=PERSON).digest()

def empty_levels():
    e = []; cur = ZERO
    for _ in range(256):
        e.append(cur); cur = h2(cur, cur)
    return e  # e[d] = empty subtree of height d

def empty_root():
    e = ZERO
    for _ in range(256):
        e = h2(e, e)
    return e

def fold(value, key, sib):
    cur = value
    for d in range(256):
        bi = 255 - d
        bit = (key[bi // 8] >> (7 - (bi % 8))) & 1
        cur = h2(sib[d], cur) if bit == 1 else h2(cur, sib[d])
    return cur

def main():
    seal36 = bytes.fromhex(sys.argv[1].removeprefix("0x"))
    if len(seal36) != 36: raise SystemExit("src_seal36 must be 36 bytes = txid(32) ‖ idx(4 LE)")
    key = hashlib.blake2b(seal36, digest_size=32).digest()                  # PLAIN blake2b-256 (matches verifier b2b256)
    e = empty_levels(); er = empty_root()
    if len(sys.argv) > 2:
        old = bytes.fromhex(sys.argv[2].removeprefix("0x"))
        if old != er:
            raise SystemExit(f"registry root {old.hex()} != empty_root {er.hex()} — this helper only does the genesis-empty insert")
    assert fold(ZERO, key, e) == er, "non-membership self-check failed"
    new_root = fold(PRESENT, key, e)
    witness = key + b"".join(e)
    print(json.dumps({"key": "0x" + key.hex(), "witness": "0x" + witness.hex(), "new_root": "0x" + new_root.hex(), "empty_root": "0x" + er.hex()}))

if __name__ == "__main__":
    main()
