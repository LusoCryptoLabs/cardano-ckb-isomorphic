//// validators/seal_nft.ak
//// One-shot minting policy for an isomorphic-binding SEAL NFT. Exactly one seal token
//// exists per bound asset; the seal UTxO (this NFT, held at binding_lock) IS the asset's
//// ownership. One-shot: mintable only in the tx that spends `seed`.
use aiken/collection/dict
use aiken/collection/list
use cardano/assets.{PolicyId, tokens}
use cardano/transaction.{Transaction, OutputReference}

validator seal_nft(seed: OutputReference) {
  mint(_redeemer: Data, policy_id: PolicyId, self: Transaction) {
    let spends_seed = list.any(self.inputs, fn(i) { i.output_reference == seed })
    let minted = self.mint |> tokens(policy_id)
    let exactly_one = dict.size(minted) == 1 && dict.values(minted) == [1]
    spends_seed && exactly_one
  }
  else(_) { fail }
}
