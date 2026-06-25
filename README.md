# Chiral

Chiral is an experiment in moving assets between Cardano and CKB without a custodian and without a
bonded committee. Instead of trusting a multisig or a validator set, each chain verifies the other's
consensus directly, inside its own scripts, on real data. The two directions are mirror images of
each other, which is where the name comes from.

It's a prototype, and I want to be upfront about that. The hard cryptography works and has run end to
end on public testnets (Cardano preview and CKB Pudge) in both directions, but this is not a product:
testnet only, unaudited, no liquidity, and the relayer is coordinator-driven. Don't put real funds
anywhere near it.

If you just want to try it, there's a small self-serve dApp and a guided testnet pilot. Start with
[docs/TRY_IT.md](docs/TRY_IT.md) - you'll need two wallets and two faucets, and you sign every
transaction yourself. There's also a sibling repo,
[cardano-ckb-bridge](https://github.com/tecmeup123/cardano-ckb-bridge), which is the boring, safe,
bonded-committee version that already works; this repo is me chasing the trust-minimized version that
one's docs flag as future work.

## The idea

A normal lock-and-mint bridge has to verify both chains on both sides, and verifying CKB's Eaglesong
proof-of-work inside a Plutus script budget is brutal. Isomorphic binding sidesteps that by being
asymmetric: an asset's ownership stays anchored to one chain's UTxOs while its state and logic live on
the other, and only the follower chain ever has to verify the anchor. I built both directions:

- Cardano to CKB is the cheap one. Ownership is anchored to a Cardano "seal" UTxO and the state lives
  on CKB. CKB checks a Mithril certificate (Cardano's stake-based BLS threshold signature) directly in
  CKB-VM, which is possible because CKB scripts can run arbitrary RISC-V crypto.
- CKB to Cardano is the hard one. Ownership is anchored to a CKB cell and the state lives on Cardano.
  Cardano verifies a Groth16 SNARK of CKB consensus (Eaglesong PoW, header MMR, tx inclusion) in Plutus
  using its BLS12-381 builtins.

## What actually works

Everything here has run on-chain and is re-checkable through CKB RPC and Koios.

Cardano to CKB:

- A full Mithril certificate verified inside CKB-VM: aggregate BLS, the stake lottery, batch-Merkle
  membership, and quorum, on a real preview cert (around 134-146M cycles, a few percent of a block).
- A light-client cell live on Pudge that only advances its stake checkpoint by verifying a real
  Mithril cert in-VM (tx 0xb7ada085), plus a tx-set authenticator (0xe4e1b0c6).
- The full binding lifecycle on-chain: genesis bind (0x0318d35f), transition (0x94d0620f), leap-out
  finalize (0x795f4bb9), driven by a real Cardano seal.

CKB to Cardano:

- A Groth16 verifier written in Aiken running on Cardano's BLS builtins, at roughly a quarter of a
  transaction's CPU budget.
- The full CKB-consensus circuit (Eaglesong PoW, ChainRoot MMR membership, CBMT tx-inclusion,
  commitment), with every gadget differential-tested against native CKB on real Pudge blocks.
- A complete round trip: CKB lock (0x4923241a), proof, Cardano verify (f99c3461), mint (21ad4a44),
  burn (6608c4c8), CKB unlock (0xde70a26d). Supply goes back to zero; conservation holds.
- A burn-gated unlock that releases the locked CKB only against a Mithril-certified burn on an
  authenticated checkpoint, so no key authorizes the spend.

There's also a permissionless relayer (it can only help liveness, it can't forge), a CI tamper/diff
gate that already caught Mithril quietly changing its message format, and an optional SP1 STARK version
of the Mithril verifier as a post-quantum path.

## What's missing

The short version: no
mainnet, no third-party audit, no liquidity, and no hardened public relayer. The dApp and pilot exist
and the on-chain mechanics are proven, but a real production deployment is not. Wrapped tokens are
minted and burned in a closed loop, so nothing is actually held or usable right now.

## Trust model

Ownership and double-spend are covered by the anchor chain's own consensus. Cross-chain soundness rests
on Mithril's honest-stake-majority assumption one way (checked in-script, no committee), and on Groth16
soundness plus CKB's proof-of-work the other way. No bonded committee, no governor in the safety path.
It is not, however, any more trust-minimized or any more post-quantum than the two chains' own
signature layers, and I don't claim otherwise.

## Layout

```
docs/          design notes, the honest gap map, the live tx-by-tx log, and TRY_IT.md to test it
spike/         the actual build - each subdir is one experiment with its own RESULTS file
  ckb-to-cardano/    the CKB->Cardano Groth16 circuit, Aiken verifier, and relayer
  cardano-to-ckb-zk/ the optional SP1 STARK-Mithril path
  mithril-verify/ light-client-cell/ burn-gated-unlock/ relay-escrow/  the Cardano->CKB pieces
dapp/          the self-serve leap dApp (React front end + node relayer back end); see dapp/TESTING.md
deploy/        VPS pilot deploy - systemd units, env example, nginx, PILOT_DEPLOY.md
cardano/       Cardano seal NFT + binding lock (Aiken) and deploy tooling
relayer/        the permissionless relayer (transcode / relay / validate)
deployed/      records of the live deployments (tx hashes, code hashes)
```

## License

MIT, see [LICENSE](LICENSE). A few vendored bits (for example under spike/sp1-ckb/vendor/) keep their
own licenses.
