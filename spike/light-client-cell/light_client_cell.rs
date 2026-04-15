//! ⚠️ SUPERSEDED SKETCH — NOT a gap, NOT built/referenced (no `[[bin]]`). The live, complete light-client
//! verifier is `advance-cert/src/main.rs` (zero stubs; verify_certificate = aggregate BLS + stake lottery +
//! Merkle + quorum) — DEPLOYED & running on Pudge (see docs/CHIRAL_STATUS.md, AdvanceCert `0xb7ada085`).
//! The `todo!()`s below are early placeholders; the real implementation lives in advance-cert/. Kept only
//! for design history — do not "finish" this; it's done elsewhere.
//!
//! light_client_cell.rs — SKELETON of the Cardano light-client cell type script (ROADMAP P2).
//! Wires the PROVEN in-script Mithril verifier (spike/mithril-verify/*: BLS aggregate + stake
//! lottery + Merkle membership, all verified in CKB-VM on a real preview cert) into a
//! self-advancing on-chain Cardano checkpoint. NOT yet a complete/tested script — it pins the
//! shape and the verify wiring; TODOs mark the remaining glue. See docs/LIGHT_CLIENT_CELL.md.
#![cfg_attr(not(test), no_std)]
#![cfg_attr(not(test), no_main)]

// The trusted Cardano checkpoint held in the cell's data (molecule-encoded in production).
pub struct LightClientState {
    pub epoch: u64,
    pub avk_root: [u8; 32],   // Mithril stake-key Merkle root (aggregate verification key)
    pub total_stake: u64,
}

// A Mithril certificate, transcoded by the relayer into a compact form (the ~27KB JSON is parsed
// off-chain; the script re-verifies the crypto). Fields mirror what the verifier needs.
pub struct CertWitness<'a> {
    pub signed_message: &'a [u8],            // = ProtocolMessage::compute_hash bytes
    pub protocol_parts: &'a [(&'a [u8], &'a [u8])], // ordered (key,value) to recompute signed_message
    pub sigmas: &'a [[u8; 48]],              // distinct winning signers' G1 sigs
    pub mvks: &'a [[u8; 96]],                // their G2 keys
    pub stakes: &'a [u64],
    pub indices: &'a [&'a [u64]],            // winning lottery indices per signer
    pub targets: &'a [[u8; 64]],             // per-party lottery targets (verified against total_stake)
    pub merkle_indices: &'a [usize],
    pub merkle_values: &'a [[u8; 32]],
    pub next_avk_root: [u8; 32],             // from protocol_message.next_aggregate_verification_key
    pub next_total_stake: u64,
}

// === The proven verifier (implemented + measured in spike/mithril-verify/*). ===
// In the real build these are one module; here they are the contract this skeleton depends on.
mod verifier {
    use super::*;
    // 1. recompute signed_message = SHA256 over ordered key||value; must equal cert.signed_message.
    pub fn check_protocol_message(_c: &CertWitness) -> bool { todo!("sha256 over parts == signed_message") }
    // 2. aggregate BLS over msgp = signed_message || avk_root, empty DST (PROVEN: verified=true).
    pub fn check_aggregate_bls(_avk_root: &[u8;32], _c: &CertWitness) -> bool { todo!("bls12_381 2-pairing") }
    // 3. eligibility: per party verify target vs total_stake (rational, once), then ev<target per
    //    index (PROVEN: 40/40 won, ~14.6k cyc/idx). 4. Merkle membership of leaves in avk_root
    //    (PROVEN: reconstructs root). 5. quorum: Σ unique indices >= k.
    pub fn check_eligibility_merkle_quorum(_state: &LightClientState, _c: &CertWitness, _k: u64) -> bool {
        todo!("per-party target verify + ev<target + batch-merkle reconstruct == avk_root + quorum")
    }
}

/// The full certificate verification: certificate is valid under `state.avk` ⇒ returns the next avk.
pub fn verify_certificate(state: &LightClientState, c: &CertWitness, k: u64) -> Option<([u8;32], u64)> {
    if !verifier::check_protocol_message(c) { return None; }
    if !verifier::check_aggregate_bls(&state.avk_root, c) { return None; }
    if !verifier::check_eligibility_merkle_quorum(state, c, k) { return None; }
    Some((c.next_avk_root, c.next_total_stake))   // epoch N+1 checkpoint
}

/// AdvanceCert type-script logic: input cell (state N) + cert ⇒ output cell (state N+1).
/// (Pseudocode shape; CKB cell I/O + type-id uniqueness omitted in the skeleton.)
pub fn advance(prev: &LightClientState, c: &CertWitness, k: u64) -> Option<LightClientState> {
    let (next_root, next_total) = verify_certificate(prev, c, k)?;
    Some(LightClientState { epoch: prev.epoch + 1, avk_root: next_root, total_stake: next_total })
}
