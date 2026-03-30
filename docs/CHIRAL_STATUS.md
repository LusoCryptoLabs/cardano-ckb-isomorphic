# Chiral (Cardano ⇄ CKB isomorphic binding protocol) — authoritative status

Two directions, each with a trust-minimized verifier on the destination chain. Conservation: an asset is
locked on the source and represented on the destination; spend-once seal ⇒ mint-once; never live on both.

## Forward leg — CKB → Cardano : COMPLETE & LIVE (fully ZK on-chain)
A Groth16 proof of CKB consensus is verified in Plutus. Built, validated on real CKB data, and executed
on real testnets with explorer-visible transactions.
- Circuit (spike/ckb-to-cardano/circuit/prover): R1 PoW (Eaglesong + Blake2b + compact-target) · R2
  ChainRootMMR membership · R3 CBMT tx-inclusion · R4 seal/commitment binding — every gadget
  differential-tested vs native CKB; trustless AdvanceCKBCert (difficulty-verify + variable-carry
  MMR-append + N-batching). On-chain verify ≈ 22.7% of a Cardano tx (groth16/, Aiken).
- Trusted setup: a real 3-party Groth16 phase-2 ceremony (verifiable); proof under the ceremony key
  accepted on-chain.
- Relayer (spike/ckb-to-cardano/relayer): proves from LIVE Pudge data -> broadcast-ready redeemer.
- LIVE round trip (spike/ckb-to-cardano/LEAP.md), all explorer-visible:
  CKB lock 0x4923241abfd2.. -> ZK proof -> Cardano verify f99c3461.. -> mint 100k ckCKB 21ad4a44..
  -> burn 6608c4c8.. (supply->0) -> CKB unlock 0xde70a26d.. . Conservation closed.

## Reverse leg — Cardano → CKB : LIVE & trustless via DIRECT Mithril verification in CKB-VM
The production reverse leg verifies a Mithril certificate DIRECTLY in CKB-VM (no STARK needed). Built,
in-script verified, and DEPLOYED on Pudge with real transactions (see docs/LIVE_STATUS.md):
- light_client_advance.rs / bound_asset_unified.rs: verify_certificate = aggregate BLS + stake-lottery
  (differential-tested == is_lottery_won on all 2330 real preview indices) + batch-Merkle + quorum;
  a real preview cert verifies in CKB-VM at ~146M cycles = 4.18% of a block.
- LIVE: Mithril-certified seal-mint 83dd51d2.. -> CKB bound-cell genesis 0x0318d35f.. -> transition
  0x94d0620f.. -> **leap-out finalize 0x795f4bb9** (block 21,358,183), each verified in-script on the
  live Pudge node against real Mithril data. The full lifecycle is closed.
- The light-client checkpoint is authenticated on-chain: AdvanceCert advances epoch 320->321 by
  verifying a real Mithril cert in-VM (164.4M cycles, 0xb7ada085); TxSetCert authenticates the
  certified tx-set root (0xe4e1b0c6). The relayer (relayer/) is built (liveness only, cannot forge),
  validated byte-for-byte vs the on-chain-accepted witness; remaining is a hosted daemon (external).

### Optional v2 optimization (NOT required): STARK-Mithril (spike/cardano-to-ckb-zk/)
Decision: STARK-Mithril — the relayer proves a valid Mithril certificate (a BLS-STM threshold multisig
of Cardano stake), CKB-VM verifies the succinct proof. (spike/cardano-to-ckb-zk/)
(succinctness + post-quantum; the direct CKB-VM path above is what's live.)
- ✅ Trust anchor on real data: our burn IS Mithril-certified; the BLS-STM multisig + tx-inclusion
  VERIFY (mithril_verify/, official mithril-client, cert epoch 1321, k=1944/m=16948/phi_f=0.2). The
  network-free guest computation runs (verify_offline).
- ✅ SP1 zkVM working in-sandbox: compile -> execute -> prove -> verify (toolchain installed manually;
  see sp1/install_toolchain.sh).
- ✅ M1 (signed_message = Sha256(protocol_message)) PROVEN in SP1 on the real cert.
- ✅ M2 (BLS12-381 aggregate, the trustless core) PROVEN in SP1 (STARK proof generated+verified):
  single multi-Miller+final-exp, ~3.3M cycles (SP1 BLS precompile cut 57.3M -> 3.3M), RAM unblocked
  via 17GB swap (~32GB effective).
- ✅ **ALL FOUR relations composed in ONE SP1 STARK** on the real cert 7356eaa1 (sp1/m2all):
  M1 + M2 + M3 (two-level Blake2s tx-inclusion) + M4 (cert-hash), with CERT_ROOT bound to the
  cardano_transactions_merkle_root part that M1 hashes and M2 signs. M2_ALL_PROVED true,
  cycles = 3,931,058, proven+verified.
- ⏳ Remaining (resource-gated, no new code): the Groth16 wrap of the STARK (wired, SP1_WRAP=groth16)
  needs a >=32GB-RAM prover or the SP1 network; then verify the wrapped proof in CKB-VM. Mithril's own
  future_snark (certs already carry aggregate_verification_key_snark) would collapse M2 to "verify the
  Mithril SNARK". NB the LIVE reverse leg already verifies the full M1..M4 directly in CKB-VM; SP1 is
  the optional succinct/PQ optimization.

## Quantum
Hash/commitment core is quantum-resistant. Signature/pairing layers (Mithril BLS, Groth16, Cardano
Ed25519, CKB secp256k1) are not — same as all production chains. Endgame: STARK-Mithril (FRI, PQ) reverse
leg; a STARK/Plonk forward verifier is the PQ upgrade there.

## Reproduce
- Forward gadgets/proof: spike/ckb-to-cardano/circuit/prover (cargo run --release --bin gadget_tests / leap_prove); Aiken: groth16/ (aiken check).
- Mithril verify: spike/cardano-to-ckb-zk/mithril_verify (cargo run; GITHUB_TOKEN for the git deps).
- SP1 M1 proof: spike/cardano-to-ckb-zk/sp1/m2 ; BLS execute: sp1/m2bls (prove needs >=32GB).
