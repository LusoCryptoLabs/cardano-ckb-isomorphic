//// END-TO-END (LIVE): the PRODUCTION value-bound + reorg-K-floor leap proof (leap_bound_windowed) accepted
//// by the on-chain Aiken verifier. One Groth16 proof attests BOTH that the leaped header has real Eaglesong
//// PoW and sits >= K_MIN deep below the checkpoint tip (window K-floor; no shallow reorg can mint) AND that
//// the minted amount/recipient are DERIVED from the on-chain bridge_lock_v1 receipt body (no free witness).
//// 5 public inputs = (window_root, seal, commitment[derived], tip_height, K) — exactly cardano_bound's
//// inputs_bind_w shape. Regenerated from /tmp/witness_bridge.json + bridge_lock_live.json (block 21,388,341,
//// receipt tx 0xcfaaf177, amount 200 CKB, recipient 2df44c71...).
//// vk + proof below are from the REAL multi-party trusted-setup CEREMONY (see circuit/ceremony/).
use g16/verifier.{VerifyingKey, Proof, verify}

test bound_windowed_leap_verifies() {
  let vk =
    VerifyingKey {
      alpha_g1: #"b14be0b3e424b7d576245e7da6d397349276ab3318a2bd5fa8514c96423adb1bcf32a7b54229e2bf698575e61d995ec8", beta_g2: #"96c95c239ad610d7712dd4aa868388674dc79d64321c4452d14c74b87c997916c65b3baa9e83596555dcdf9db87e384216d8fb0b472d1ca077cbedbc9fa898827cf80462ad73a27d691145f5cad4a37f852039d53274ca4df23f5a0d1e728abe",
      gamma_g2: #"a937723cefa0e752e3762acb5191dac72507677ab53fbe61beae1e99e3500f530f33aef0163e4cd3747cd7efa973d23a15756d79e0da199875184aad90e2c335ff727057bac5f006d75913b0d6f8853fd0d4f854b719881ff783cc2a6db4bf44", delta_g2: #"a31bf037b38d8d3ca59def5f47b853075600d17d2e8eab6c36cc7f667a9bab5c69671f30474c4e1f79ee0dcbb811158a18c1007da13eb436a6d2c3b77f1387a4ea294fd1469d140a64cad405b72b6ecf99dd3643e940a8e17c693acb9825c64e", ic: [#"8a86667c1c125d45c8ea793a84f7e70c8b52e8ecb3242dc7ad58a9f9073fcbd347c76b40bae555b40ecb20fef6a2c731",#"a95e3f3f67562db33579f5130342d6c9e97d68d7bcc50460805c6406dc5b77ff2d1540dbff8f4490387b38c119af0ec2",#"b569570aed14131035b946677ef83bbe10077f3359028695ff9f18b73a0247cfe76bcc29e97e8a998530048c9b4463a7",#"b27aa56ce9e9245266df99ff5df6dded4d8689722a676232e5a4848e644fa2a03588c9547fc5f16e74aab4412b686df5",#"8653bcda328b5f037b83ffc810f10241c5e5069650c7f3bcddc29183531a9fa9984ed7baad672b6f943dd4eb9c7bcfab",#"a60f8b4d480d28edb9a7c6328f82f2220f672e6536fb2cf7939a90df1ed0105381f6ce05523c9d060aba345417fe31f2"],
    }
  let proof = Proof { a: #"a220d998142ba0dc05f891c5dfe7b808f4a048beff3f6de9dfae337b36ace22c388d4b9a1a4ec6ce98cf53cb1b46094d", b: #"b1295e494a31fd7b2f17ea5ef1d642a44084f2c7383109722f4110c359443101010db3a896ec326db3e0f9e2525641521348fe89504a7a7f0294652dc40a32cd17edbcd78294ba4a20081125408ef9f2d0b51d46cef1a39200b00cd99b0f3a47", c: #"8013483f5ed8682a7a5673de36d8e5ee236798e386b237995eab0b6d63ce8a511d98fe20232bfd1792bc3e51f7aad9f2" }
  verify(vk, proof, [41635068647168944954009992505280861266476499445945086624775210147991309069160, 1580336594980841998889247533439485665687685432334501066150903235913979112142, 38201670710410045569512885805973334057060653559194782302660510860053608275231, 21388353, 12])
}
