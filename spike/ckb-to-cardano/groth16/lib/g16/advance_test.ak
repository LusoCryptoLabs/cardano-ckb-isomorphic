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
//// Source: circuit/prover/src/bin/advance_live.rs -> the CEREMONY redeemer (circuit/ceremony/
//// advance_live_ceremony_redeemer.json): phase-1 PoT + phase-2 delta, 3 contributors each, forgeries
//// rejected, toxic waste destroyed -- the vk AdvanceCKBCert actually bakes on-chain. Fits the leap's 2^21
//// SRS tier (1,389,535 constraints); the deep CKB-MMR variant (advance_prove.rs) is 2^22-2^23.
use g16/verifier.{VerifyingKey, Proof, verify}

// The real advance (header-chain follower) CEREMONY verifying key (ic length 8 => 7 public inputs).
fn advance_vk() -> VerifyingKey {
  VerifyingKey {
    alpha_g1: #"8b681f64912fc6d8691a6be7b92a02395f9d365db3eb7c0d190761e32ec44c7fbf96116f2bb604366bba36e7c00623f1",
    beta_g2: #"b8d4c34763f49e08eaae87db598a16fa972aff10f88532b1a3cd8e5b56cef2aabb41ed6e4e3e23ce81c06a962ff821e6013da83eac21a06f92d2318508371fc3202a757c4b68dcebffd35ec7a796cfc5f1077fcc779f11d9ffbc4eebc17e5ea7",
    gamma_g2: #"93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8",
    delta_g2: #"a93fcea7168a22420e18ddbae46ec1bf1a4e2889b75be81ee7c5e7ca8dff73515f503e9e43a042036a0d68813ce6337e176c33d18b73b918f78210a1caf9a906cf8b5dbb452929a0dba727075ab333b478e7824c2d53b6ac6b3c69b0353647d1",
    ic: [
      #"8a05dae6b727425245adb2cc87a1e1807ff0283d24fcee29ae1f21555673be7c7edeea337a9d788d02504ac2952a0688",
      #"89a5c4f53ec146736f13dccd8bf729b95db284d67193526939447a312147cfbcf986d629554ad3b96abd7b6a16ad6be1",
      #"90f1dfe385d893579cce8968125eb96460dd241270ab78567470760b5596b73d19aa0ad3b69d0c052d01d9fb34270956",
      #"b72ec461e201110cfa4da6168a42a0325c06c652dbb6ee22fb700658410e2eeb913c6b46b7653efce7f949080ee5770f",
      #"8f7190b767c21a75c50e9155b525ca0c40f1d0f01668ac79cdd04ab7ebc3dc7ed3e20ab798ad5cca53f48bffce489b4c",
      #"aab333be1f7142c87714efdc7455d0d541ac6b771293ce95e51cfba6ed84025b296812fc36ce3b445b1c0b69ca16a4b6",
      #"83457c412de4cf5273ed9444c6a9a6410b25edd349ea9de8e3b2fb97dee8c78f8d5c8d03fed0733ca167a8909d9c8ef3",
      #"a5a0e4e74f4f4b24548ce0854b8f8847c1cc56516fec8ae9783b943ac45286f725a43b7d218d35f427eea394d09a2038",
    ],
  }
}

fn advance_proof() -> Proof {
  Proof {
    a: #"a61b428f5da7f2e725e5726010f50054356d395bd9f905e51d855b0802c467324be90c8074f336bcb451331b9d06e0b0",
    b: #"9834018e859791a650e4090eb5ab774017bf17401a46f76bf5fa194d7aef9cf2b8fa5a865c4e68fa9b8bdd97d13492a50b602c42001c793379caa1c06d07430d813da699596bf97598b9136bd7de707b6daa16a7f13cb30b12ad5924bf739eee",
    c: #"b0b752b3f67ba6a1b2c7e7e74b10d7b32eee136300436800f5b5f6898c3417920b50682091eb6dee6b9cb523cd7783b9",
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

// NEGATIVE CONTROL: tamper the new_window_root public input (index 5) - the on-chain verifier must reject,
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
