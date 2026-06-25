//// END-TO-END (LIVE): the PRODUCTION value-bound + reorg-K-floor leap proof (leap_bound_windowed) accepted
//// by the on-chain Aiken verifier. One Groth16 proof attests BOTH that the leaped header has real Eaglesong
//// PoW and sits >= K_MIN deep below the checkpoint tip (window K-floor; no shallow reorg can mint) AND that
//// the minted amount/recipient are DERIVED from the on-chain bridge_lock_v1 receipt body (no free witness).
//// 5 public inputs = (window_root, seal, commitment[derived], tip_height, K) - exactly cardano_bound's
//// inputs_bind_w shape. Regenerated from /tmp/witness_bridge.json + bridge_lock_live.json (block 21,388,341,
//// receipt tx 0xcfaaf177, amount 200 CKB, recipient 2df44c71...).
//// vk + proof below are from the REAL multi-party trusted-setup CEREMONY (see circuit/ceremony/).
//// vk + proof below are from the REAL multi-party trusted-setup CEREMONY (see circuit/ceremony/).
//// vk + proof below are from the REAL multi-party trusted-setup CEREMONY (see circuit/ceremony/).
use g16/verifier.{VerifyingKey, Proof, verify}

test bound_windowed_leap_verifies() {
  let vk =
    VerifyingKey {
      alpha_g1: #"8ee81b5a4d943bbffca08dbd844375d4c72da3ee0cd5fee5b1674ad167b4fbfeb13b3c2ddc6ce9d30703433e518aab64", beta_g2: #"96089fdf41203791526ee71aeeb2ebbf2a9720a568840cb77bb3ced0f6cb0de7e019f07df9970e2c58e41743b5ef40fc1782d8f7cb0a2e0926161e1ad52c2377078dae16605e5a75ac050ec914e48683908a3ae50a9baae2f144567e613174b6",
      gamma_g2: #"93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8", delta_g2: #"99056bc0174081d5c0cc855ad1b0447b5f2f5111ad49bdd1b279f21f237d414c3b9280d935f4390eb99cbf8c49154005142c30398591e798c72b0c41a313b86028d4e63677538647ac4cc90e31f7735a1537fdf8d96ff9fabd5b43589365ed49", ic: [#"81f97f7842d018246e03e6ddfd63d9e4866bcbcb0b05b6920a4eb083f2b2e8ae5fb6ef8ef3563347dea72c2ce0281b7e",#"a9fafc72fb8c41e0c0c428cff6ef979332381259b6fc85833b7b65a529d0cdcdce4a41aa8e5ea027ef48d30f5d64e054",#"879684bdf5e3537993ae67254d38d27daa423eeaed0f1a99d4b5a2ac79e77ce24e6b6acfc8f0791cda202729e89c39cf",#"a877557e1c62a7a269f2ab94a50a71babf8926ab66d0b9aef9a2be401b8e17a1779bc7765b2ee7e21d674c15cb14a418",#"9620e03f4d21bef63d0f1751ef703100cff7e58ca7df7595a911ccee1fee79230466ff24931e6de7f7dc08509a40e954",#"a5d92ad7d196fcb92989e8e4fd6a79758042051b48f423b42753b4de9f992d1569857c7a5e3f9557407360e6723e77c4"],
    }
  let proof = Proof { a: #"a18ecbf61d8ae174ca9aa03be1cc2ee089982c8258966380a53a91eedcfe7fb168555bac4bf831ca9a99b6c0e0ba48d3", b: #"a6e5795faf90b786aeb250dc1c149e68f1359a7863d2cfef3cded0ac786055a4e99957c77628071323abd4d498bcc2ac10504dca2337b02b8e479292cea3ae5fa1fd11ce9260329ee9cf6b4412ea51b8de5c1e13f443b55df9a358200f08a62c", c: #"978321f904ebfe83ce7c4a1f88c5da7d34593f7871727b8dca88b6d137b7da5b941621fb8c4041a3682e925fa68191d4" }
  verify(vk, proof, [7806206333684049857615430111125711096747055906625223418297821684630235840878, 1580336594980841998889247533439485665687685432334501066150903235913979112142, 38201670710410045569512885805973334057060653559194782302660510860053608275231, 21388353, 12])
}
