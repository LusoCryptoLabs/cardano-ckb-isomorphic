//! smt_replay.rs - Sparse Merkle Tree replay verification for CKB-VM (no_std).
//!
//! O(1) replay-set scaling (audit M1, docs/REPLAY_SCALING.md): the state cell carries
//! a 32-byte `processed_root` instead of an unbounded `processed` list. The replay
//! check at assert becomes a proof-checked transition:
//!   * `verify_replay_smt(prev_root, next_root, nonce, proof)` - the nonce is ABSENT
//!     in prev_root (value 0) and PRESENT in next_root (value MARK), proven by ONE
//!     compiled Merkle proof. A single-leaf update changes only the leaf, not the
//!     siblings, so the SAME proof recomputes both roots - which makes "next is prev
//!     with exactly this one nonce inserted" provable (two independent proofs would be
//!     insecure: an attacker could pass a next_root for a tree that drops history).
//!
//! Hasher = CKB blake2b (`b"ckb-default-hash"`), matching `blake160`/`commit`, so one
//! off-chain tree (same crate) serves on- and off-chain.
//!
//! CRATE CHOICE (audit M1 de-risk): the **classic** `sparse-merkle-tree` (0.6.1,
//! default-features off) is used - it cross-compiles C-free for riscv (we supply the
//! pure-Rust `blake2b-ref` hasher) AND allows zero-value leaves (non-membership) AND
//! its keys-only `compile` produces a value-agnostic proof. The `restricted-*` fork was
//! rejected: it forbids zero-value leaves (`ForbidZeroValueLeaf`) and bakes the value
//! into the compiled proof. See REPLAY_SCALING.md.

extern crate alloc;
use alloc::vec;
use blake2b_ref::{Blake2b, Blake2bBuilder};
use sparse_merkle_tree::{traits::Hasher, CompiledMerkleProof, H256};

/// CKB-native blake2b hasher for the SMT (matches `blake160`/`commit` personalisation).
pub struct CkbBlake2bHasher(Blake2b);

impl Default for CkbBlake2bHasher {
    fn default() -> Self {
        CkbBlake2bHasher(Blake2bBuilder::new(32).personal(b"ckb-default-hash").build())
    }
}

impl Hasher for CkbBlake2bHasher {
    fn write_h256(&mut self, h: &H256) {
        self.0.update(h.as_slice());
    }
    fn write_byte(&mut self, b: u8) {
        self.0.update(&[b]);
    }
    fn finish(self) -> H256 {
        let mut out = [0u8; 32];
        self.0.finalize(&mut out);
        out.into()
    }
}

/// Non-zero leaf value meaning "this nonce has been processed". (SMT default = 0.)
pub const MARK: [u8; 32] = [1u8; 32];

/// True iff `proof` shows `nonce` ABSENT in `prev_root` and PRESENT in `next_root`
/// - i.e. a valid single-leaf insertion (replay protection at assert time). The same
/// compiled proof verifies both roots because only the leaf value changed.
pub fn verify_replay_smt(
    prev_root: &[u8; 32],
    next_root: &[u8; 32],
    nonce: &[u8; 32],
    proof: &[u8],
) -> bool {
    let key: H256 = (*nonce).into();
    let absent = CompiledMerkleProof(proof.to_vec())
        .verify::<CkbBlake2bHasher>(&(*prev_root).into(), vec![(key, H256::zero())])
        .unwrap_or(false);
    let present = CompiledMerkleProof(proof.to_vec())
        .verify::<CkbBlake2bHasher>(&(*next_root).into(), vec![(key, MARK.into())])
        .unwrap_or(false);
    absent && present
}

// In `cargo test` the crate builds with std (see bridge_lock.rs cfg_attr), so we drive
// a real tree to generate REAL proofs and assert the contract logic accepts valid
// insertions and rejects replays / wrong roots / tampering. Run on the HOST target:
//   cargo test --target x86_64-unknown-linux-gnu
#[cfg(test)]
mod tests {
    use super::*;
    use sparse_merkle_tree::{default_store::DefaultStore, SparseMerkleTree};

    type Smt = SparseMerkleTree<CkbBlake2bHasher, H256, DefaultStore<H256>>;
    fn h(n: u8) -> H256 {
        [n; 32].into()
    }
    fn arr(r: &H256) -> [u8; 32] {
        let mut a = [0u8; 32];
        a.copy_from_slice(r.as_slice());
        a
    }

    fn setup() -> (Smt, H256) {
        let mut t = Smt::default();
        t.update(h(9), MARK.into()).unwrap(); // some prior processed nonces
        t.update(h(5), MARK.into()).unwrap();
        let prev = *t.root();
        (t, prev)
    }

    // keys-only compile => a value-agnostic proof that recomputes both roots.
    fn proof_for(t: &Smt, key: H256) -> alloc::vec::Vec<u8> {
        t.merkle_proof(vec![key]).unwrap().compile(vec![key]).unwrap().0
    }

    #[test]
    fn absent_then_insert_passes() {
        let (mut t, prev) = setup();
        let nonce = h(7);
        let proof = proof_for(&t, nonce); // proof against prev (nonce absent)
        t.update(nonce, MARK.into()).unwrap(); // off-chain insert
        let next = *t.root();
        assert!(verify_replay_smt(&arr(&prev), &arr(&next), &arr(&nonce), &proof));
    }

    #[test]
    fn replay_rejected() {
        // nonce already processed in prev_root: its proof shows value MARK, not 0, so
        // the "absent in prev_root" check fails (and a no-op next == prev can't insert).
        let (t, _) = setup();
        let nonce = h(9); // already in the tree
        let prev = *t.root();
        let proof = proof_for(&t, nonce);
        let next = prev; // attacker pretends nothing changed
        assert!(!verify_replay_smt(&arr(&prev), &arr(&next), &arr(&nonce), &proof));
    }

    #[test]
    fn wrong_next_root_rejected() {
        let (mut t, prev) = setup();
        let nonce = h(7);
        let proof = proof_for(&t, nonce);
        t.update(nonce, MARK.into()).unwrap();
        let bogus_next = h(123); // not the real single-leaf update
        assert!(!verify_replay_smt(&arr(&prev), &arr(&bogus_next), &arr(&nonce), &proof));
    }

    #[test]
    fn tampered_proof_rejected() {
        let (mut t, prev) = setup();
        let nonce = h(7);
        let mut proof = proof_for(&t, nonce);
        t.update(nonce, MARK.into()).unwrap();
        let next = *t.root();
        if !proof.is_empty() {
            proof[0] ^= 0xff; // corrupt a byte
        }
        assert!(!verify_replay_smt(&arr(&prev), &arr(&next), &arr(&nonce), &proof));
    }

    #[test]
    fn insert_into_empty_tree_passes() {
        // genesis: empty-tree root, first nonce inserted.
        let mut t = Smt::default();
        let prev = *t.root();
        let nonce = h(1);
        let proof = proof_for(&t, nonce);
        t.update(nonce, MARK.into()).unwrap();
        let next = *t.root();
        assert!(verify_replay_smt(&arr(&prev), &arr(&next), &arr(&nonce), &proof));
    }
}
