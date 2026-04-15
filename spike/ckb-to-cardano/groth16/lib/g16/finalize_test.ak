//// END-TO-END (LIVE): the FINALIZE-branch counterpart of the CKB->Cardano leap (closes re-audit N-2).
//// A Groth16 proof from the finalize circuit on LIVE Pudge state (block 0x145ae82) — R1 PoW + R2 MMR +
//// R3 tx-inclusion + R4 seal binding — whose commitment is computed in-circuit as the seal-specific
//// FINALIZE commitment blake2b256("FIN" || seal). It is accepted by the SAME on-chain Aiken verifier the
//// cardano_bound.ak `Finalize` branch uses, and its public_inputs[2] equals field_of(finalize_commitment(seal)).
use aiken/builtin
use g16/ckbcert.{field_of}
use g16/verifier.{VerifyingKey, Proof, verify}

test finalize_proof_verifies_onchain() {
  let vk =
    VerifyingKey {
      alpha_g1: #"b14be0b3e424b7d576245e7da6d397349276ab3318a2bd5fa8514c96423adb1bcf32a7b54229e2bf698575e61d995ec8", beta_g2: #"96c95c239ad610d7712dd4aa868388674dc79d64321c4452d14c74b87c997916c65b3baa9e83596555dcdf9db87e384216d8fb0b472d1ca077cbedbc9fa898827cf80462ad73a27d691145f5cad4a37f852039d53274ca4df23f5a0d1e728abe",
      gamma_g2: #"a937723cefa0e752e3762acb5191dac72507677ab53fbe61beae1e99e3500f530f33aef0163e4cd3747cd7efa973d23a15756d79e0da199875184aad90e2c335ff727057bac5f006d75913b0d6f8853fd0d4f854b719881ff783cc2a6db4bf44", delta_g2: #"a31bf037b38d8d3ca59def5f47b853075600d17d2e8eab6c36cc7f667a9bab5c69671f30474c4e1f79ee0dcbb811158a18c1007da13eb436a6d2c3b77f1387a4ea294fd1469d140a64cad405b72b6ecf99dd3643e940a8e17c693acb9825c64e", ic: [#"9394a988d8a83b0fc908f9a42e5a575d14eaf24a2a5b92939473fc0672370e30352dfea133b7be81235014ed18a8d449",#"aa1f17d791f698e3dc4a6a88ea1d55c6b863756939fa1c1ba1654ad2d8fbe937747cadd82363a27c25b75958f1c88f13",#"808f90ec453a28d45ed40439b282fba460912806a42bd1cfcfa8c7ad88a460c609c505211b37f6d93cc886de50ea4827",#"a72cc6318d4331bb488f069ae0801edf34cb9e6282d7547074bbe8f6ac6e7bbca66b175ee6e4c011831382c0ddeb1b54"],
    }
  let proof = Proof { a: #"83018677057a6a05b80649d820aebfcc4ec8a57e37efa9da73eef7687ca83819e35c9b3edb40223a3aa9bfcea4e0daf8", b: #"97096ef615021fcb7843de7993ca99214e663ffc23a038a22ba9fbc70464194945f7029c4201cab8a9a31adc853d73970b9dac867c671b346dfc4905bd23ffb0f0e55ae5df51773721c377c2fb55c120cdd3bd267fdf42264d5477154d9a45f7", c: #"8e9326e58b865c0c8c44d2c5495db94ea0d763c453d7c14181859d82897f063a19e97d7f245d052ce81f7fe153d0d91c" }
  verify(vk, proof, [8164594514254600893432411695136792912727798414870430771390069282052469740282, 13036920860526642713416161171862666891249943253554113278707260465089896301871, 34029185564559816989111259500952817310182057526982375500321300857569366870070])
}

// The finalize commitment public input equals field_of(blake2b_256("FIN" || seal)) — the exact value
// cardano_bound.ak `finalize_commitment` recomputes, so the Finalize branch's `inputs_bind` will match.
test finalize_commitment_matches_validator() {
  let seal = #"2fc594f3bec38a6874decd1155e65ba97e87c536a60be70304683d6bbea2d21c"
  let comm = builtin.blake2b_256(builtin.append_bytearray(#"46494e", seal))
  field_of(comm) == 34029185564559816989111259500952817310182057526982375500321300857569366870070
}
