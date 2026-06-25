//! mldsa.rs - post-quantum committee signature verification (audit / QUANTUM_RESISTANCE.md P1).
//!
//! The bridge's authorization today rests on ECC signatures (CKB secp256k1, Cardano
//! Ed25519), which Shor's algorithm breaks. On CKB - where scripts are arbitrary RISC-V -
//! the bridge can verify a POST-QUANTUM signature itself, replacing the secp256k1-multisig
//! composition with an in-script M-of-N ML-DSA verifier.
//!
//! Primitive: **ML-DSA-44 (Dilithium2, FIPS 204)** via the pure-Rust `fips204` crate.
//! De-risked: VERIFY needs no OS randomness, so this cross-compiles C-free to the bare-metal
//! `riscv64imac-unknown-none-elf` contract target (the `ml-dsa-44` feature WITHOUT
//! `default-rng`). ML-DSA-65 (level 3) is a drop-in more-conservative option (swap the
//! feature/module) at a larger pubkey/sig size.
//!
//! STATUS: P1 complete on the CKB side. The verifier is benchmarked on CKB-VM (**one verify
//! ≈ 4.39M cycles**, a 3-of-5 ≈ 13.7M - trivial vs CKB's ~3.5e9 per-block budget) AND WIRED
//! IN: `verify_committee` is `bridge_lock`'s `is_committee_authorized` / `is_governor_authorized`.
//! The state cell stores 32-byte blake2b hashes of the members' ML-DSA public keys; the
//! spending witness (`input_type`) carries full pubkeys + signatures over the tx hash; the
//! script accepts iff >= threshold DISTINCT members signed. Covered end-to-end by the on-VM
//! suite (real keygen/sign in tests-vm). Remaining (live deployment, not contract): off-chain
//! signer services emit ML-DSA; challenge.rs's governor is still ECC-composed (separate leg).

use fips204::ml_dsa_44;
use fips204::traits::{SerDes, Verifier};

/// ML-DSA-44 public-key and signature byte lengths (FIPS 204).
pub const PK_LEN: usize = ml_dsa_44::PK_LEN; // 1312
pub const SIG_LEN: usize = ml_dsa_44::SIG_LEN; // 2420
/// One committee authorization entry in the witness = pubkey ++ signature.
pub const PAIR_LEN: usize = PK_LEN + SIG_LEN;

/// Verify one ML-DSA-44 signature over `msg` (empty context string). Returns false on any
/// malformed public key - never panics. This is the primitive `is_committee_authorized`
/// will run for each claimed committee signer (M-of-N), over the serialized action/claim.
pub fn verify_mldsa(pk_bytes: [u8; PK_LEN], msg: &[u8], sig_bytes: [u8; SIG_LEN]) -> bool {
    match ml_dsa_44::PublicKey::try_from_bytes(pk_bytes) {
        Ok(pk) => pk.verify(msg, &sig_bytes, &[]),
        Err(_) => false,
    }
}

/// blake2b-256 of a public key (`ckb-default-hash`), the 32-byte committee identifier
/// stored in the state cell (so the cell holds compact hashes, not full 1312-byte keys).
pub fn pk_hash(pk: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut h = blake2b_ref::Blake2bBuilder::new(32).personal(b"ckb-default-hash").build();
    h.update(pk);
    h.finalize(&mut out);
    out
}

/// Post-quantum M-of-N committee check (QUANTUM_RESISTANCE.md P1). `auth` is a concatenation
/// of `(pubkey ++ signature)` entries from the witness; `committee` is the set of authorized
/// 32-byte pubkey HASHES from the state cell. Returns true iff at least `threshold` DISTINCT
/// committee members have a valid ML-DSA signature over `msg`. Each member counts once;
/// non-members and invalid/duplicate signatures are ignored. Replaces the secp256k1-multisig
/// composition with an in-script post-quantum verifier.
/// The DISTINCT committee members (32-byte pubkey hashes) that produced a valid ML-DSA
/// signature over `msg` in `auth`, in auth-blob order. Used by the assert path to
/// RECORD who authorized an assertion (so a later fraud resolution slashes exactly
/// them). Unlike `verify_committee`, it does not short-circuit - every provided entry
/// is checked - so the asserter should provide exactly its quorum's pairs.
pub fn committee_signers(committee: &[[u8; 32]], msg: &[u8], auth: &[u8]) -> alloc::vec::Vec<[u8; 32]> {
    let mut seen: alloc::vec::Vec<[u8; 32]> = alloc::vec::Vec::new();
    if auth.len() % PAIR_LEN != 0 {
        return seen;
    }
    for chunk in auth.chunks_exact(PAIR_LEN) {
        let (pk, sig) = chunk.split_at(PK_LEN);
        let h = pk_hash(pk);
        if !committee.contains(&h) || seen.contains(&h) {
            continue;
        }
        let mut pkb = [0u8; PK_LEN];
        pkb.copy_from_slice(pk);
        let mut sigb = [0u8; SIG_LEN];
        sigb.copy_from_slice(sig);
        if verify_mldsa(pkb, msg, sigb) {
            seen.push(h);
        }
    }
    seen
}

pub fn verify_committee(committee: &[[u8; 32]], threshold: usize, msg: &[u8], auth: &[u8]) -> bool {
    if threshold == 0 || auth.len() % PAIR_LEN != 0 {
        return false;
    }
    let mut seen: alloc::vec::Vec<[u8; 32]> = alloc::vec::Vec::new();
    for chunk in auth.chunks_exact(PAIR_LEN) {
        let (pk, sig) = chunk.split_at(PK_LEN);
        let h = pk_hash(pk);
        // member of the committee, and not already counted this tx?
        if !committee.contains(&h) || seen.contains(&h) {
            continue;
        }
        let mut pkb = [0u8; PK_LEN];
        pkb.copy_from_slice(pk);
        let mut sigb = [0u8; SIG_LEN];
        sigb.copy_from_slice(sig);
        if verify_mldsa(pkb, msg, sigb) {
            seen.push(h);
            if seen.len() >= threshold {
                return true; // short-circuit once threshold distinct members verified
            }
        }
    }
    false
}

// Host tests (std + the `default-rng` dev-dependency) drive a real keygen/sign so the
// verify path is exercised end-to-end. Run on the host:
//   cargo test --target x86_64-unknown-linux-gnu
#[cfg(test)]
mod tests {
    use super::*;
    use fips204::traits::Signer;

    #[test]
    fn keygen_sign_verify_roundtrip() {
        let (pk, sk) = ml_dsa_44::try_keygen().unwrap();
        let msg = b"committee authorizes: AssertMint nonce/amount/recipient/finalize_at";
        let sig = sk.try_sign(msg, &[]).unwrap();
        let pkb = pk.into_bytes();
        assert!(verify_mldsa(pkb, msg, sig), "a valid ML-DSA signature must verify");
        let mut tampered = sig;
        tampered[0] ^= 1;
        assert!(!verify_mldsa(pkb, msg, tampered), "a tampered signature must be rejected");
        assert!(!verify_mldsa(pkb, b"a different message", sig), "wrong message must be rejected");
    }

    #[test]
    fn wrong_key_rejected() {
        let (_pk, sk) = ml_dsa_44::try_keygen().unwrap();
        let (other_pk, _other_sk) = ml_dsa_44::try_keygen().unwrap();
        let msg = b"msg";
        let sig = sk.try_sign(msg, &[]).unwrap();
        assert!(!verify_mldsa(other_pk.into_bytes(), msg, sig), "a different key must not verify");
    }

    // CROSS-LIBRARY INTEROP (off-chain JS committee -> on-chain Rust verifier): a
    // signature produced by `@noble/post-quantum` ml_dsa44 (the sidecar's signing lib)
    // MUST verify under fips204 (this contract) with an EMPTY context. The vector is
    // committed at ckb-sidecar/fixtures/mldsa_interop_vector.json and regenerated by
    // ckb-sidecar/mldsa_interop_check.mjs; this locks the guarantee into `cargo test`
    // so the two libraries can never silently drift apart.
    #[test]
    fn noble_js_signature_verifies_under_fips204() {
        let v = include_str!("../../../ckb-sidecar/fixtures/mldsa_interop_vector.json");
        let field = |k: &str| -> alloc::vec::Vec<u8> {
            let pat = alloc::format!("\"{}\": \"0x", k);
            let after = v.split(&pat).nth(1).expect("field present");
            let hexs = after.split('"').next().unwrap();
            (0..hexs.len()).step_by(2).map(|i| u8::from_str_radix(&hexs[i..i + 2], 16).unwrap()).collect()
        };
        let pk = field("pk");
        let msg = field("msg");
        let sig = field("sig");
        assert_eq!(pk.len(), PK_LEN, "pk len");
        assert_eq!(sig.len(), SIG_LEN, "sig len");
        // the on-chain committee identifier must match what the JS side computed.
        let expected_hash = field("pkHash");
        assert_eq!(&pk_hash(&pk)[..], &expected_hash[..], "pk_hash must agree JS<->Rust");
        let mut pkb = [0u8; PK_LEN];
        pkb.copy_from_slice(&pk);
        let mut sigb = [0u8; SIG_LEN];
        sigb.copy_from_slice(&sig);
        assert!(verify_mldsa(pkb, &msg, sigb), "a @noble/post-quantum signature must verify under fips204");
    }
}
