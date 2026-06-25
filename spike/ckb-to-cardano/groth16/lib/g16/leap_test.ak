//// END-TO-END (complete statement): a REAL Groth16 proof from the assembled CKB-consensus LEAP
//// circuit on REAL block 21,341,101 - R1 PoW (in-circuit compact-target decode) + R2 ChainRootMMR
//// (HeaderDigest) membership tying the proven header to the checkpoint + R3 the tx bound to the
//// header's transactions_root via a REAL CBMT path + R4 commitment - verified on-chain by the SAME
//// Aiken Groth16 verifier the cardano_bound binding lock uses. R1..R4 all present.
//// SEC D1/D2 (regenerated): the commitment is now STANDARD blake2b-256 (matches `builtin.blake2b_256`) and
//// the seal public input is BOUND to the block-included CBMT leaf (seal == proven tx hash). Public inputs
//// are the reducing `field_of` residues (mod the BLS scalar order).
//// vk + proof below are from the REAL multi-party trusted-setup CEREMONY (see circuit/ceremony/).
//// vk + proof below are from the REAL multi-party trusted-setup CEREMONY (see circuit/ceremony/).
use g16/verifier.{VerifyingKey, Proof, verify}

test leap_proof_verifies_onchain() {
  let vk =
    VerifyingKey {
      alpha_g1: #"88ae1f9ad314efde5bcaf675de17dec0d3d99628d4cb1d069b932f774d3533d375af52f55163448e55ef5164e028a1f5", beta_g2: #"a596e0f380572227a0aea186225893be4d9deaab0e06be6e0b850c3864ee7bcc48113723a9e5efd07319c05764119f3e15c55a4ea1558337fad494b8dbe0880cb276901908e155997f6ad9ab2b3a0f15dd73d833572a44ce9f06694938295994",
      gamma_g2: #"93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8", delta_g2: #"91f2eb5adb470f3333eb8559949a29bf640f8ba5f6c28e5793cd5731ae9f51a84f68617b85c24c900f6fb09f947064d408c6db3b7d1b1353ccff9c42185d9be255b6933a3a36f9750549e04270e9170d5e671eacfd46b14a7b58931fafe57d79", ic: [#"b270d95a36764f39a63a6e2c60ead93a7f4891d72d3158be35028628327de13bd1768bdbb9cbc4069a8a853d28a228dd",#"8daa15c3079218a87549bb29a040b1e85c946d361923523b43ee9b1c01bbb823bff9adb44a39fc427a903377be2f3d32",#"800850d12bf0f0e53c2fce07808d86ba1f5927ac2f807054fd3eb0dcd2146a4ff75ffd397fa223a0533785e27cc14d72",#"a87f11dfd88a457a9f5e59c158dda89e4e1f5dd3826553da8cdbc5b8693e4ab25c59e120b4bb9b02d0e79e65c51c6638",#"b20d90e693aa903a3f3ae41017e1a1e40b0151f15ffe0153ddfb600e19602cf7d8574752e43e200831fe32ae157d29a5",#"acc10a3ecd91b48b6edc83ea8c4eff9f69efe3d2a6c8834126616681b72e0779f4c00b66f927f86f9d55fb5f8216c32d"],
    }
  let proof = Proof { a: #"afd7c607f87877080f9021a934f13adf63cf90e90d8455b0a7f3732891d966807993f2203023cb7b9b4f75ebf3d89519", b: #"921034d7028f2f4d270938f19c65f82e964d7a6e84a4002c389eb5c7da35c9e6ce24b348a6cb3ef79a7b21214963f91300bf7da91a14e1bba796a4c67d5a3d8115ed19effc4b22c17a59be052060df79404feb0242651a63e73350cc181f6ad9", c: #"9998bc57d7b05bff89fc3511cdd34447cda2684e855aae99d9b63a3b1c594d089a15e4c7403581232f33b4dbaf1b304e" }
  verify(vk, proof, [28310521350029174782803729649459910887792735815837643005172217438257825718518, 14767272357315540033014598146567367545545869346047846303877462720874513896676, 10260736901354840877089021162481495933119005982082170012766374501396596446316, 21341113, 12])
}
