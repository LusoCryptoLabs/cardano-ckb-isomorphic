//// END-TO-END (complete statement): a REAL Groth16 proof from the assembled CKB-consensus LEAP
//// circuit on REAL block 21,341,101 — R1 PoW (in-circuit compact-target decode) + R2 ChainRootMMR
//// (HeaderDigest) membership tying the proven header to the checkpoint + R3 the tx bound to the
//// header's transactions_root via a REAL CBMT path + R4 commitment — verified on-chain by the SAME
//// Aiken Groth16 verifier the cardano_bound binding lock uses. R1..R4 all present.
//// SEC D1/D2 (regenerated): the commitment is now STANDARD blake2b-256 (matches `builtin.blake2b_256`) and
//// the seal public input is BOUND to the block-included CBMT leaf (seal == proven tx hash). Public inputs
//// are the reducing `field_of` residues (mod the BLS scalar order).
use g16/verifier.{VerifyingKey, Proof, verify}

test leap_proof_verifies_onchain() {
  let vk =
    VerifyingKey {
      alpha_g1: #"b14be0b3e424b7d576245e7da6d397349276ab3318a2bd5fa8514c96423adb1bcf32a7b54229e2bf698575e61d995ec8", beta_g2: #"96c95c239ad610d7712dd4aa868388674dc79d64321c4452d14c74b87c997916c65b3baa9e83596555dcdf9db87e384216d8fb0b472d1ca077cbedbc9fa898827cf80462ad73a27d691145f5cad4a37f852039d53274ca4df23f5a0d1e728abe",
      gamma_g2: #"a937723cefa0e752e3762acb5191dac72507677ab53fbe61beae1e99e3500f530f33aef0163e4cd3747cd7efa973d23a15756d79e0da199875184aad90e2c335ff727057bac5f006d75913b0d6f8853fd0d4f854b719881ff783cc2a6db4bf44", delta_g2: #"a31bf037b38d8d3ca59def5f47b853075600d17d2e8eab6c36cc7f667a9bab5c69671f30474c4e1f79ee0dcbb811158a18c1007da13eb436a6d2c3b77f1387a4ea294fd1469d140a64cad405b72b6ecf99dd3643e940a8e17c693acb9825c64e", ic: [#"8cb279fa26ce09f8fdc511b61aa1c89e45008b838f31809c903ee021803db8ad41fe0ede577fbb056880172acca2191f",#"a80826eb70311157bd30d238577f2ff3dacd117007c7de4b5cb7ce5b06fd655fb8c71d64c741d887186f25b0e11e70e4",#"b161c8f6589f113d33a51bdd824560cde74b30d4e6bf52a76a036ca1387cb95c39cca678a36c027f251c1084a6083d4a",#"93179492f7910d8f29986386546f7f8f100ee2451a3489af2544bc83f5bb3e78e5e6baf498f960c5b13c77184141a5c7"],
    }
  let proof = Proof { a: #"a7db7b014edde5b7c657d8a891beb8d3a5b4b9557b81684e2048b72809a8e3e9c467582b985aeb413a97d05cafa3b10a", b: #"88ce69b2e2f44944d71cf8036202bf7dbb5a0c26b16647f2526ca818bce2439ea90a37cc69e245fd31ed86548ebade940291fc2468f43982fd8baa82dadc2c66bbe5efd87f48cb3c5fdb75d66c56bb56e21b5c1f635aa2af3f4f5fbe394d5c06", c: #"a09a855a9b7206cf907823d2333a540e632c2cebd2744a2487e3b8c280a877a797d38fc934031bf06371b8afa778afad" }
  verify(vk, proof, [31717729688939745289925800127337770540377636260416842835918687947839970001234, 14767272357315540033014598146567367545545869346047846303877462720874513896676, 10260736901354840877089021162481495933119005982082170012766374501396596446316])
}
