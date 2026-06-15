//// END-TO-END: a REAL AdvanceCKBCert proof for the HEADER-CHAIN FOLLOWER advance (advance_live.rs), the
//// production advance circuit. Header 21,341,104 is appended to a checkpoint anchored at its parent
//// (21,341,103): the circuit proves R1 PoW(new header) <= target, PARENT-LINK (new.parent_hash ==
//// checkpoint chain_root = prior tip hash), DIFFICULTY (new_total == old_total + difficulty(new)), the
//// WINDOW ring-buffer update (insert new block hash at slot height mod W, old root verified then
//// recomputed), and authenticates new_tip_height. new chain_root == the new tip's block hash
//// (f9255030..., the real hash of 21,341,104).
//// Accepted by the SAME Groth16 verifier advance_ckbcert.ak uses on-chain (7 PIs in this exact order:
////   old_root, old_total_difficulty, new_root, new_total_difficulty, old_window_root, new_window_root, new_tip_height)
//// -> the checkpoint window root + tip are trustless AND proven, the chain is PoW + parent-linked + heaviest
//// (cumulative work) from the pinned genesis anchor.
////
//// Source: circuit/prover/src/bin/advance_live.rs -> circuit/ceremony/advance_live_redeemer.json (seeded test
//// setup; the LIVE re-genesis must rebake advance_ckbcert with the CEREMONY vk, not this seeded one). Fits the
//// leap's 2^21 SRS tier (1,389,535 constraints); the deep CKB-MMR variant (advance_prove.rs) is 2^22-2^23.
use g16/verifier.{VerifyingKey, Proof, verify}

// The real advance (header-chain follower) verifying key (ic length 8 => 7 public inputs).
fn advance_vk() -> VerifyingKey {
  VerifyingKey {
    alpha_g1: #"b14be0b3e424b7d576245e7da6d397349276ab3318a2bd5fa8514c96423adb1bcf32a7b54229e2bf698575e61d995ec8",
    beta_g2: #"96c95c239ad610d7712dd4aa868388674dc79d64321c4452d14c74b87c997916c65b3baa9e83596555dcdf9db87e384216d8fb0b472d1ca077cbedbc9fa898827cf80462ad73a27d691145f5cad4a37f852039d53274ca4df23f5a0d1e728abe",
    gamma_g2: #"a937723cefa0e752e3762acb5191dac72507677ab53fbe61beae1e99e3500f530f33aef0163e4cd3747cd7efa973d23a15756d79e0da199875184aad90e2c335ff727057bac5f006d75913b0d6f8853fd0d4f854b719881ff783cc2a6db4bf44",
    delta_g2: #"a31bf037b38d8d3ca59def5f47b853075600d17d2e8eab6c36cc7f667a9bab5c69671f30474c4e1f79ee0dcbb811158a18c1007da13eb436a6d2c3b77f1387a4ea294fd1469d140a64cad405b72b6ecf99dd3643e940a8e17c693acb9825c64e",
    ic: [
      #"956e2405976c8db7472245813261c0d81e5e69eb39668452a8f3cc3247344aa0554b8ea61b5c07b117687d6b3b04c5df",
      #"aaa23d45ac1dbcce542afa549b98f92aecf7f2c3941e7f5caaa112ef73809a8b5c1549812b20ead86ffb53b13ab04990",
      #"b0a7780bca00912fd2085eecbf91e82835b6b864ec5658101587068860f0c5fd92e662dae7af98e90a0c784d21749498",
      #"a01a1a0cd7dfd00b1753d964e20434d7c4684bff209d9a685492a0e434ecd2f1ed9b1edaba0048c066ae7ab90584b276",
      #"a167b02ff5c0814d0b14327a089ce45e9a94b04d3a4f6f81eb1d4b26fbe41ffdf1239a9710a7389a7b74412d3841ea3f",
      #"8fdc0d2c179ce116d55a9b0985046a1444c9bc59c68f75ec4791de8fb5953b5ad699010122a56e31416d730d9042dee4",
      #"a35890a84582c86cd75108a4b2eb0277a6bae32523782f308b3f24bb7fc0b5c6804a5b8d298db885921a16174e0d6d12",
      #"aef23dd8d20c60fa473232ba241e5a3e9581fd7a68555a117372eade1e832ae9622488fb606083b8214adf450e1b30e7",
    ],
  }
}

fn advance_proof() -> Proof {
  Proof {
    a: #"a6efa5161a434f7f46988806bb8da893b0af1be99ad4b57bd11794f49cba6fe25f4c6c7fd7c24dee0b7ac77d70303671",
    b: #"a02cc29fdc196d59d46ce93c48a655d128d627be9c310a7526d739a365a74aef391ec91a4c30741043d79082d9a53b1719346443f5281f5efba1af845057f72cbce9e0748ed1d87a23e4200b479bd288b78a0410a29ed5013bc3dc7810445d8b",
    c: #"b7c8cbd7b412684324b81c085a5b2117417275ec0f0ad8597f2b573ade2dc6c710bcc8b79746a97b5cd9d74c09fed2d0",
  }
}

// The 7 public inputs in the exact order advance_ckbcert.ak binds them:
//   old_root, old_total_difficulty, new_root, new_total_difficulty, old_window_root, new_window_root, new_tip_height
const adv_pi: List<Int> =
  [
    10474656301376581020935943632627198982157846046608663361569706379475250813036,
    0,
    29856070891671071138634521309201950435683667613490428394575559246455071843833,
    8759561681808011807466626565899339577920394703656577381477395925833472802814,
    41611970084863457754907777103662880542494170798307052699026275529199782303094,
    34622319808027169263999950872225516813215544943525791678299870892468758393737,
    21341104,
  ]

test advance_proof_verifies_onchain() {
  verify(advance_vk(), advance_proof(), adv_pi)
}

// NEGATIVE CONTROL: tamper the new_window_root public input (index 5) — the on-chain verifier must reject,
// so a forged window advance cannot be accepted. (advance_ckbcert.ak additionally re-binds these PIs to the
// continuing checkpoint datum, but the SNARK verify alone already pins the window transition.)
test advance_proof_rejects_tampered_new_window_root() fail {
  let bad =
    [
      10474656301376581020935943632627198982157846046608663361569706379475250813036,
      0,
      29856070891671071138634521309201950435683667613490428394575559246455071843833,
      8759561681808011807466626565899339577920394703656577381477395925833472802814,
      41611970084863457754907777103662880542494170798307052699026275529199782303094,
      34622319808027169263999950872225516813215544943525791678299870892468758393738,
      21341104,
    ]
  verify(advance_vk(), advance_proof(), bad)
}
