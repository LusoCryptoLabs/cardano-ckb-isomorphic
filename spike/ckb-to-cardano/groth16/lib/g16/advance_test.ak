//// END-TO-END: a REAL AdvanceCKBCert proof with a PROVEN MMR-append + window ring-buffer update — header
//// 21,341,104 appended to the ChainRootMMR (leaves 21,341,101..103) AND inserted into the depth-6 window
//// at slot height mod 64. new_root/new_window_root are COMPUTED in-circuit (full-carry MMR merges each
//// summing total_difficulty; window old-root verified then recomputed), R1 PoW + parent-link +
//// difficulty_verify tie the leaf to reality, and the height is bound as the 7th public input (new_tip).
//// Accepted by the SAME Groth16 verifier advance_ckbcert.ak uses on-chain (7 PIs:
////   old_root, old_diff, new_root, new_diff, old_wroot, new_wroot, new_tip_height)
//// -> the checkpoint window root + tip are trustless AND proven, not assumed.
////
//// Source: circuit/prover/src/bin/advance_prove.rs -> circuit/ceremony/advance_redeemer.json (seeded test
//// setup; the LIVE re-genesis must rebake advance_ckbcert with the CEREMONY vk, not this seeded one).
use g16/verifier.{VerifyingKey, Proof, verify}

// The real advance verifying key (ic length 8 => 7 public inputs).
fn advance_vk() -> VerifyingKey {
  VerifyingKey {
    alpha_g1: #"b14be0b3e424b7d576245e7da6d397349276ab3318a2bd5fa8514c96423adb1bcf32a7b54229e2bf698575e61d995ec8",
    beta_g2: #"96c95c239ad610d7712dd4aa868388674dc79d64321c4452d14c74b87c997916c65b3baa9e83596555dcdf9db87e384216d8fb0b472d1ca077cbedbc9fa898827cf80462ad73a27d691145f5cad4a37f852039d53274ca4df23f5a0d1e728abe",
    gamma_g2: #"a937723cefa0e752e3762acb5191dac72507677ab53fbe61beae1e99e3500f530f33aef0163e4cd3747cd7efa973d23a15756d79e0da199875184aad90e2c335ff727057bac5f006d75913b0d6f8853fd0d4f854b719881ff783cc2a6db4bf44",
    delta_g2: #"a31bf037b38d8d3ca59def5f47b853075600d17d2e8eab6c36cc7f667a9bab5c69671f30474c4e1f79ee0dcbb811158a18c1007da13eb436a6d2c3b77f1387a4ea294fd1469d140a64cad405b72b6ecf99dd3643e940a8e17c693acb9825c64e",
    ic: [
      #"b8e01610087bc5f0aa938ec1a960974432aefd3c0a06583de3621c04b0a85088cff48b2f699efe087a3e0c7600f3c187",
      #"89fca9975a92304b4cb1e978d00135037b781fe749d789b1f9bb0eb48bee408859863d29bc8554f1e8d0037d1464a738",
      #"90be5d34dad63cd1f4d3ae57aee46480ef0079981b8545d237d12d6dca37e0f57a63edb6d78277f85bdf1da0de8a525e",
      #"8ec44f777a9e615a3db30044a8b9de8e115075e2fe08ae2325c8e16a0489d59f88a790e71894d17f264e0e95d3bf3c73",
      #"8dd2a91a0823f0331efb5cc77e52847c4adb20a31bdcc1a10550a4ad0e9297fdcf9ce6bc4d6e47075be10f178a881d2a",
      #"aa9531b7b55335bca399289ebec8aebda341b69b2d811c6b10c4695d79c4fe4089ca47175b37da991afc9edc3b6fc9db",
      #"87a46214377657d4cc674244bb48f83ec87667fa1041ab20b2595763535aae7c51ae6b1ffe87788ac25b9cb3c42ad2a8",
      #"b8cf758d4589f5c982fd8b533859168cbc3844f4eb3c5fa728b9eb0e617230d557ace3784f780191e83ba6a2d6b13f75",
    ],
  }
}

fn advance_proof() -> Proof {
  Proof {
    a: #"8dc5b329af14dbb0073b722c428ae46333b216a5a4a5ad8fad9ee6c88d256c721d48ea9d673aabff71d37184877c345a",
    b: #"8b924253e3eea6f42fe56388fe74ab5c15c5ff0163e8efd7741dcae6ac57320974e582f9a8c8ba2d60161a277d71c5e209d36ff58a162f9d6a606d13d13eeada52e1a226b6d14183dc4d10c7927534a5bf4f2863907d68be9de0f2633ad544b1",
    c: #"a91aeb31f7860dd133d646dbf0781aa80d3d076732ad0929052551f5bcdbc9605f94e24c459bef1441b1dc044c7aab6c",
  }
}

// The 7 public inputs in the exact order advance_ckbcert.ak binds them:
//   old_root, old_total_difficulty, new_root, new_total_difficulty, old_window_root, new_window_root, new_tip_height
const adv_pi: List<Int> =
  [
    38576495415038396351487052532173251479263127381474700775304829449567596866267,
    4441540965425963261708038308067552215015079749592906593847897773831069106174,
    47108760298172182770853230283734977916048840044792844219027840290251640410064,
    2282530607234938988828744179151658533562422272561071200033148697829867257854,
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
      38576495415038396351487052532173251479263127381474700775304829449567596866267,
      4441540965425963261708038308067552215015079749592906593847897773831069106174,
      47108760298172182770853230283734977916048840044792844219027840290251640410064,
      2282530607234938988828744179151658533562422272561071200033148697829867257854,
      41611970084863457754907777103662880542494170798307052699026275529199782303095,
      34622319808027169263999950872225516813215544943525791678299870892468758393737,
      21341104,
    ]
  verify(advance_vk(), advance_proof(), bad)
}
