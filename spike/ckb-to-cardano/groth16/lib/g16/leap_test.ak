//// END-TO-END (complete statement): a REAL Groth16 proof from the assembled CKB-consensus LEAP
//// circuit on REAL block 21,341,101 — R1 PoW (in-circuit compact-target decode) + R2 ChainRootMMR
//// (HeaderDigest) membership tying the proven header to the checkpoint + R3 the tx bound to the
//// header's transactions_root via a REAL CBMT path + R4 commitment — verified on-chain by the SAME
//// Aiken Groth16 verifier the cardano_bound binding lock uses. R1..R4 all present.
//// SEC D1/D2 (regenerated): the commitment is now STANDARD blake2b-256 (matches `builtin.blake2b_256`) and
//// the seal public input is BOUND to the block-included CBMT leaf (seal == proven tx hash). Public inputs
//// are the reducing `field_of` residues (mod the BLS scalar order).
//// vk + proof below are from the REAL multi-party trusted-setup CEREMONY (see circuit/ceremony/).
use g16/verifier.{VerifyingKey, Proof, verify}

test leap_proof_verifies_onchain() {
  let vk =
    VerifyingKey {
      alpha_g1: #"8e96cc489b2599dc5755109e1c333800353144a40cfa09a4b5d9af639f5cb64dd775b677d340f3cc2257b4dc329c6618", beta_g2: #"a6b9e738476eb8da7027b8f59ccd406b285b5adb1d85afd848503e23fb6a2a2aece7597f232d5286b957a350b269cf160faa18de7a3fc0cfcd4b82cbda4a04b1526327409bf0334d1f972b8b2b5ea65a70b9e5ce055168f22ccbadecc9a78a6a",
      gamma_g2: #"93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8", delta_g2: #"b4545094d5b16218d0a5f77925cd19121130e70628c03b23188d2f5ac7014a19d5b03e978bc682059cdf9d6f52b193ab0b582f99281b48c5882292bf712e5e3ed16a748b6f3a68a15e52f5b4b83d14756659459c5de8c91380459c2480050d5a", ic: [#"a388e9efceaf9e0a7861c1347505f282128c8c8948501eef2eacb2de02e9269f6000a52fa42423d047c8faaed74bc7aa",#"af7beb9cd3e3f4109b79e1fdeebf033eafd0e99aeed07ccb516b8a1a90ff01715cb3831cfeb0c27e4d491f4b1241707d",#"a747d5f3ef4b4c37e842f0c40ec3e3dd3440c50efe03214bbfd554f772c878a30fef7a4a02a87e62d8b930baf1a72130",#"8ee39f448cbe237fa1c0c5e539d69d39c83e8ebb28c4c8a589b793ef282bb1f4912ea1db6e8ca55810daa7180a7e86ce"],
    }
  let proof = Proof { a: #"98c4e1cc2bc8ef212dcf2f01b6c0e1d93fe5a173253318b8d7f2b4c2c316fff94af54bb31eb3e3d537d651ccce9cb15b", b: #"b70652ce8efb5f10e9d733aba4a4e4fb089f949e88151516f9b4f49bcf756d9a049de41ef2956eada6d5e815035a9bd206ddeb265c8a2839937e393b4c0d167db10f1fd17857d5cb3019f5c1bb565ed7d2e472b54b02180e778e3193b8216a12", c: #"8e84ab050107a2a58ff68352da39e1eeba84b97466d688dd7197cd67890c6fe5e9ff9cf2fd32239be99f209f47a506de" }
  verify(vk, proof, [31717729688939745289925800127337770540377636260416842835918687947839970001234, 14767272357315540033014598146567367545545869346047846303877462720874513896676, 10260736901354840877089021162481495933119005982082170012766374501396596446316])
}
