//// seal_set.ak - a self-contained, fixed-depth (128-bit) SPARSE MERKLE TREE over consumed CKB seals, the
//// Cardano mirror of the CKB-side `burn_nullifier_registry`'s SMT (SEC N-FIN-1 / the forward-leg replay
//// class). A key (a 32-byte CKB seal = the anchor tx hash, D2) is "present" (consumed) or "absent"; the tree
//// path is the key's LOW 128 bits (the last 16 bytes). An insertion is authenticated by a single set of 128
//// sibling hashes that must take the key from value 0 (ABSENT, under the old root = NON-MEMBERSHIP) to
//// `present` (under the new root). Because the live old root pins the siblings (collision-resistance of
//// blake2b-256), the only satisfying new root is the genuine single-leaf update - so a seal can be inserted
//// at most once, ever. That is what makes "one seal ⇒ one Cardano lineage/outcome" enforceable.
////
//// DEPTH = 128 (was 256): a 256-deep insert costs ~15.6M Plutus mem in the full leap TxInfo, which (with the
//// other 3 scripts) exceeds the Conway 16.5M per-tx limit; 128 halves the blake2b chain to ~8M and fits.
//// SECURITY: a 128-bit path keeps REPLAY-ONCE intact (each path admits one insert, ever - the soundness this
//// enforces). The only effect of the truncation is a LIVENESS edge: two distinct seals sharing their low 128
//// bits map to one path, so the second's leap is blocked (never a double-mint). A collision needs a ~2^64
//// birthday grind over REAL CKB lock-tx hashes (each attempt costs a real on-chain lock) - infeasible to
//// weaponise; for mainnet, re-evaluate vs. the budget (or split the insert into a prior tx to keep 256).
use aiken/builtin
use aiken/collection/list

/// The seal-nullifier registry datum: the current SMT root over consumed seals.
pub type SealSet {
  root: ByteArray,
}

/// The seal-nullifier registry spend redeemer: the seal `key` (32B) to consume + its 128 merkle siblings.
pub type Insert {
  key: ByteArray,
  sibs: List<ByteArray>,
}

/// 32 zero bytes - an ABSENT leaf (and the seed of the empty-subtree hashes).
pub const zero: ByteArray =
  #"0000000000000000000000000000000000000000000000000000000000000000"

/// 32 bytes of 0x01 - a PRESENT (consumed) leaf. Any fixed non-zero value works; consistency is all.
pub const present: ByteArray =
  #"0101010101010101010101010101010101010101010101010101010101010101"

fn h2(l: ByteArray, r: ByteArray) -> ByteArray {
  builtin.blake2b_256(builtin.append_bytearray(l, r))
}

fn pow2(n: Int) -> Int {
  when n is {
    0 -> 1
    1 -> 2
    2 -> 4
    3 -> 8
    4 -> 16
    5 -> 32
    6 -> 64
    _ -> 128
  }
}

/// Fold a leaf `value` at `key`'s 256-bit path up through the `sibs` (LEAF-FIRST) to a root. At depth `d`
/// from the leaf the path bit is bit (255-d) of `key`, MSB-of-byte-0 first (identical to the CKB script).
fn fold_go(value: ByteArray, key: ByteArray, sibs: List<ByteArray>, d: Int) -> ByteArray {
  when sibs is {
    [] -> value
    [sib, ..rest] -> {
      let bi = 255 - d
      let byte = builtin.index_bytearray(key, bi / 8)
      let bit = byte / pow2(7 - bi % 8) % 2
      let cur =
        if bit == 1 {
          h2(sib, value)
        } else {
          h2(value, sib)
        }
      fold_go(cur, key, rest, d + 1)
    }
  }
}

pub fn fold(value: ByteArray, key: ByteArray, sibs: List<ByteArray>) -> ByteArray {
  fold_go(value, key, sibs, 0)
}

/// The root of the EMPTY 128-deep tree (all leaves absent) = E[128].
fn empty_up(e: ByteArray, d: Int) -> ByteArray {
  if d == 128 {
    e
  } else {
    empty_up(h2(e, e), d + 1)
  }
}

pub fn empty_root() -> ByteArray {
  empty_up(zero, 0)
}

/// A sound single-key insertion: `key` was ABSENT under `old_root` (non-membership) and is PRESENT under
/// `new_root`, witnessed by exactly 128 siblings. Caller must also enforce `list.length(sibs) == 128`.
pub fn inserts(
  old_root: ByteArray,
  new_root: ByteArray,
  key: ByteArray,
  sibs: List<ByteArray>,
) -> Bool {
  fold(zero, key, sibs) == old_root && fold(present, key, sibs) == new_root
}

// ---- tests: the soundness core (mirror of the CKB registry's in-VM tests) ----

/// build the empty-subtree sibling list [E[0], E[1], ..., E[255]] (leaf-first) - the siblings for inserting
/// the first key into an empty tree.
fn empties_go(e: ByteArray, d: Int, acc: List<ByteArray>) -> List<ByteArray> {
  if d == 128 {
    acc
  } else {
    empties_go(h2(e, e), d + 1, [e, ..acc])
  }
}

/// The sibling list for inserting the FIRST key into an empty tree (= the empty-subtree roots, leaf-first).
/// Exposed for provers/tests; on-chain insertions carry their own siblings.
pub fn empty_sibs() -> List<ByteArray> {
  // empties_go prepends, producing [E[255],..,E[0]]; reverse to leaf-first [E[0],..,E[255]].
  list.reverse(empties_go(zero, 0, []))
}

const key_a: ByteArray =
  #"2fc594f3bec38a6874decd1155e65ba97e87c536a60be70304683d6bbea2d21c"

test inserts_into_empty_tree() {
  let sibs = empty_sibs()
  let old_root = empty_root()
  let new_root = fold(present, key_a, sibs)
  inserts(old_root, new_root, key_a, sibs)
}

test non_membership_of_empty_holds() {
  // an absent key folds (value 0) to exactly the empty root.
  fold(zero, key_a, empty_sibs()) == empty_root()
}

test replay_rejected() {
  // SEC N-FIN-1: after key_a is inserted (root = new_root), trying to insert it AGAINST that root fails -
  // the non-membership fold(0, key_a, sibs) yields the empty root, not new_root.
  let sibs = empty_sibs()
  let new_root = fold(present, key_a, sibs)
  // attacker presents the same siblings against the post-insert root:
  !inserts(new_root, fold(present, key_a, sibs), key_a, sibs)
}

test empty_sibs_has_128() {
  list.length(empty_sibs()) == 128
}
