# A real SP1 STARK proof of CKB consensus — generated AND verified on this box

The companion to `spike/pq-fri-verify/`. That spike showed a hand-rolled post-quantum **verifier** runs *in
CKB-VM*; this one shows a **production zkVM prover (SP1 v6 / Plonky3)** generating a real **core-STARK proof
of a CKB-consensus kernel**, end-to-end, on a 15 GB / 4-core commodity box — no GPU, no cluster, **no Groth16
wrap** (so the proof is hash-based ⇒ post-quantum). This retires the "the prover is ≥32 GB-gated" caveat: the
heavy 32 GB step was the non-PQ Groth16 wrapping we explicitly don't want; the PQ **core** proof fits here.

## What is proven

The guest (`program/`, runs in the SP1 zkVM) verifies a **CKB block-header chain** — exactly the consensus
predicate the bridge checkpoint depends on (`docs/PQ_STRATEGY.md`, and the Cardano-side `c_pinned`
`chain_root` / `total_difficulty`):

- **parent linkage** — each header's `parent_hash` equals the previous block hash (blake2b-256, ckb-default-hash),
- **proof-of-work** — each block's **Eaglesong** PoW meets the **compact-target** difficulty,
- **sequential height** + agreed difficulty, and
- **cumulative work** — accumulated into `total_work` at full **U256** precision.

It commits the public checkpoint `(genesis_parent, compact_target, tip_hash, total_work, count)`. The host
(`script/`) **mines** a real low-difficulty Eaglesong chain, runs the guest, and generates + verifies the
proof. The shared logic is in `lib/` (`ckb-chain-lib`).

**Real CKB primitives (upgraded from the earlier stand-ins):** PoW is **Eaglesong** via CKB's upstream
`eaglesong` crate; difficulty is CKB's **`compact_to_target`** (nBits-style) with **U256** targets; work
accumulates as **U256**; and the chain accumulator is a real **Merkle Mountain Range** — `chain_root` is the
MMR root over all block hashes (the light-client commitment the checkpoint pins), not just the final block
hash. So the proof now attests the genuine CKB-consensus transition `(genesis, target) → (chain_root,
total_work)`.

**Wired to the checkpoint (`sp1-ckb` → `checkpoint`).** The guest commits
`(genesis, compact_target, chain_root, tip, total_work, count)`; the host decodes these public values and
feeds them as a checkpoint **advance** — `out_state = (epoch+1, chain_root, total_work)` — enforcing the
transition rules (monotone epoch, heaviest-chain on U256 `total_work`). On-chain, that advance is gated by
**verifying this SP1 proof**: native (~2.3 G cyc, `sp1-verify-cost`) or via the recursion (~300 M,
`pq-recursion`). The data flow and rules are demonstrated end-to-end here.

## Measured (SP1 v6.2.3, `SP1_PROVER=cpu`, this 15 GB / 4-core box)

| chain (real Eaglesong) | guest cycles | prove time | verify | peak RSS |
|---|---|---|---|---|
| 16 blocks | ~1.0 M | 109 s | ✅ | 11.9 GB |
| 32 blocks (execute) | 1,941,602 | — | — | — |

A real SP1 **core-STARK** proof of **real CKB consensus** (Eaglesong + compact-target + U256),
**generated and verified locally**. Eaglesong is heavier than the old blake2b stand-in (~60 K cyc/block vs
~6 K), so on this 15 GB box the core-proving ceiling is ~16–24 blocks (~1–1.5 M cycles, ~12 GB); more blocks
or the compressed proof need ≥32–64 GB — a resource limit, not a feasibility one.

## Soundness — an invalid chain is unprovable

`--tamper` corrupts one block before proving. The guest's `verify_chain` returns `None` ⇒ it panics ⇒ the
execution exits non-zero. SP1's `verify` (with no expected status code) **requires a successful exit**, so it
**rejects** the proof: `REJECTED — proof does not verify as a successful run (UnexpectedExitCode(1))`. You
can run the prover on a false statement, but you cannot obtain a proof that *verifies*.

## Reproduce

```
export PATH="$HOME/.sp1/bin:$HOME/.cargo/bin:$PATH" SP1_PROVER=cpu
cd program && cargo prove build && cd ..        # build the guest ELF (succinct toolchain)
cd script && cargo build --release && cd ..     # build the host (sp1-sdk)
./target/release/ckb-chain --execute --blocks 256          # cycle count, no proof
./target/release/ckb-chain --prove   --blocks 32           # real proof: PROVED ... / VERIFIED ...
./target/release/ckb-chain --prove   --blocks 32 --tamper  # invalid chain: REJECTED (unprovable)
```

## Scope / how this connects

Two complementary halves of the post-quantum forward leg, both now demonstrated on commodity hardware:

1. **Verifier in CKB-VM** (`spike/pq-fri-verify/`) — a hash-only FRI/STARK verifier, 46–47 M cycles
   (~1.3 % of a CKB block), measured in ckb-debugger.
2. **Production prover, here** (this spike) — SP1 proves a CKB-consensus kernel in ~1–1.5 min / ≤13 GB.

The remaining integration is to verify an SP1 proof **on-chain in CKB-VM**: SP1 core proofs are over
KoalaBear + Poseidon2, whereas the `pq-fri-verify` verifier is over Goldilocks + blake2b, so closing the loop
needs an SP1-proof verifier compiled to CKB-VM (a known, separate build — SP1 ships a `no_std` verifier).
What "do it all" establishes: **both the prover and a post-quantum verifier of CKB-relevant statements run,
for real and in budget, on this machine.**

(`target/` — multi-GB SP1 build + proving artifacts — is git-ignored; rebuild with the commands above.)
