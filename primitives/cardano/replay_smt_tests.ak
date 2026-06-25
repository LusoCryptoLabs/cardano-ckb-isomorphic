// replay_smt_tests.ak - GENERATED (do not edit by hand). Cross-impl parity for the
// M1 replay MPF: proofs produced OFF-CHAIN by @aiken-lang/merkle-patricia-forestry
// (the relayer's library) are accepted by the ON-CHAIN aiken verifier that
// bridge_state.assert_ok uses. Regenerate via the snippet in docs/REPLAY_SCALING.md.
use aiken/merkle_patricia_forestry.{Branch, Proof} as mpf

const processed_mark: ByteArray = #"01"

// a trie of already-processed nonces (4 seeds) - its committed root.
const prev_root: ByteArray = #"2980631ce96cde9b08b6767c336f077d17d7d1facdc312b141f3766bc3d07df7"
// the root AFTER inserting `new_nonce` (value = processed_mark).
const next_root: ByteArray = #"2f357a4e5b7be7b51680ca310335766167a339c6f5c393bcc9a402bc42f3ee33"
const new_nonce: ByteArray = #"8fe6d4f16cabe5d583aa0472cebcf1e8be9362095dcc7f471d59a4e35d4b62ba"
const present_nonce: ByteArray = #"a976be9ca2908d688af99f2457c87650edb8e8bfb9c6ff5ea0e13b12131b452f"

// non-membership proof for new_nonce against prev_root.
const proof_absent: Proof = [
    Branch { skip: 0, neighbors: #"0a6ad362b8eb983963e65fe10ab107953acccf6bb4e270a73cacde42211fe3d1b69a75467c65f14529ce1e86c2a3a48124455743a0d9707260ca2caf46c70a100eb923b0cbd24df54401d998531feead35a47a99f4deed205de4af81120f9761a7e709e99b7f08c325c6ec75003449cd5b582d2feea22e5c3275b2b3cf066e36" },
  ]

// membership proof for present_nonce against prev_root.
const proof_present: Proof = [
    Branch { skip: 0, neighbors: #"0a6ad362b8eb983963e65fe10ab107953acccf6bb4e270a73cacde42211fe3d139685970b3f50a9d3d4a1d7a3cf6ac352ec6b348b70c5c7b484fc3cb6e9ba9cd840dd4bebb78bbb077f8fa0e84917f1ff6b1259e5ca4af53019e26fa952672030000000000000000000000000000000000000000000000000000000000000000" },
  ]

// A fresh nonce: proven absent, inserted -> the new root equals the recorded one.
// This is EXACTLY what bridge_state.assert_ok checks (replay scaling, constant size).
test assert_inserts_fresh_nonce() {
  let next =
    mpf.from_root(prev_root)
      |> mpf.insert(new_nonce, processed_mark, proof_absent)
      |> mpf.root
  next == next_root
}

// Non-membership is provable for the fresh nonce against the prev root.
test fresh_nonce_is_absent() {
  mpf.from_root(prev_root) |> mpf.miss(new_nonce, proof_absent)
}

// An already-processed nonce is present with the mark (membership proof).
test present_nonce_is_member() {
  mpf.from_root(prev_root) |> mpf.has(present_nonce, processed_mark, proof_present)
}

// REPLAY: inserting an already-present nonce must ABORT (no valid exclusion proof
// exists for it) - bridge_state rejects the re-assert. `fail` = the body must error.
test replay_insert_rejected() fail {
  let next =
    mpf.from_root(prev_root)
      |> mpf.insert(present_nonce, processed_mark, proof_present)
      |> mpf.root
  next == next_root
}

// The produced next root genuinely advances (distinct from the prev root).
test next_root_advances() {
  let next =
    mpf.from_root(prev_root)
      |> mpf.insert(new_nonce, processed_mark, proof_absent)
      |> mpf.root
  next != prev_root
}
