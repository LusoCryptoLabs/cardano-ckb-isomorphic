//! Differential/tamper harness (Phase 4): runs the in-script Mithril verifier logic against a REAL
//! preview-cert fixture and asserts (a) it ACCEPTS the genuine cert, (b) its compute_hash reproduces
//! mithril's own `signed_message`, and (c) it REJECTS every single-component tamper (soundness).
//! Guards the in-script verifier against silent breakage from upstream Mithril format changes.
pub mod verifier;
#[allow(dead_code)]
pub mod cert_fixture;

#[cfg(test)]
mod difftest {
    use crate::verifier::*;
    use crate::cert_fixture::*;

    fn msgp() -> Vec<u8> { MSGP.to_vec() }
    fn parties() -> [(&'static [u64], &'static [u8;48], u64); 2] {
        [(IDX0, &SIGMA0, STAKE0), (IDX1, &SIGMA1, STAKE1)]
    }
    fn flip(v: &[u8], i: usize) -> Vec<u8> { let mut x=v.to_vec(); x[i]^=0x01; x }

    // (b) our compute_hash reproduces mithril's OWN signed_message field (cross-check vs mithril-common)
    #[test]
    fn compute_hash_matches_mithril_signed_message() {
        assert_eq!(compute_signed_message(PARTS).as_slice(), &MSGP[..SIGNED_MESSAGE_LEN]);
    }
    // (a) ACCEPT the genuine real cert
    #[test]
    fn bls_aggregate_verifies_real() {
        assert!(aggregate_bls(&[&SIGMA0, &SIGMA1], &[&MVK0, &MVK1], &msgp()));
    }
    #[test]
    fn lottery_all_indices_win_real() {
        assert!(lottery_quorum(&parties(), &msgp(), TOTAL, C_NUM, C_DEN, K));
    }
    #[test]
    fn merkle_reconstructs_avk_root_real() {
        assert_eq!(merkle_root(&[MLEAF0, MLEAF1], &[MVAL0], MINDICES, NR_LEAVES).as_slice(), &AVK_ROOT[..]);
    }
    // (c) SOUNDNESS - every single-component tamper is REJECTED
    #[test]
    fn tamper_sigma_rejected() {
        assert!(!aggregate_bls(&[&flip(&SIGMA0,5), &SIGMA1], &[&MVK0, &MVK1], &msgp()));
    }
    #[test]
    fn tamper_mvk_rejected() {
        assert!(!aggregate_bls(&[&SIGMA0, &SIGMA1], &[&flip(&MVK0,7), &MVK1], &msgp()));
    }
    #[test]
    fn tamper_message_rejected() {
        assert!(!aggregate_bls(&[&SIGMA0, &SIGMA1], &[&MVK0, &MVK1], &flip(&msgp(),0)));
    }
    #[test]
    fn tamper_avk_root_in_msgp_rejected() {
        let n=MSGP.len(); assert!(!aggregate_bls(&[&SIGMA0, &SIGMA1], &[&MVK0, &MVK1], &flip(&msgp(),n-1)));
    }
    #[test]
    fn tamper_signed_message_part_rejected() {
        let bad = flip(PARTS[0].1, 3);
        let mut p = PARTS.to_vec(); p[0] = (PARTS[0].0, Box::leak(bad.into_boxed_slice()));
        assert_ne!(compute_signed_message(&p).as_slice(), &MSGP[..SIGNED_MESSAGE_LEN]);
    }
    #[test]
    fn tamper_merkle_leaf_rejected() {
        assert_ne!(merkle_root(&[&flip(MLEAF0,9), MLEAF1], &[MVAL0], MINDICES, NR_LEAVES).as_slice(), &AVK_ROOT[..]);
    }
    #[test]
    fn tamper_stake_breaks_lottery() {
        let lowered: [(&[u64], &[u8;48], u64); 2] = [(IDX0, &SIGMA0, STAKE0/8), (IDX1, &SIGMA1, STAKE1)];
        assert!(!lottery_quorum(&lowered, &msgp(), TOTAL, C_NUM, C_DEN, K));
    }
}
