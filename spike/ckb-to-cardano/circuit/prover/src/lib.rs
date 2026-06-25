//! CKB-consensus circuit gadgets (BLS12-381 Fr, ark-r1cs-std), differential-tested vs native CKB.
pub mod eag_const;
pub mod eaglesong_gadget;
pub mod blake2b_gadget;
pub mod merkle_gadget;
pub mod ckb_mmr;
pub mod mmr_gadget;
pub mod difficulty_gadget;
pub mod setup_mpc;
