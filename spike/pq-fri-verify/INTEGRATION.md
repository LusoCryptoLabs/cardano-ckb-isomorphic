# The post-quantum verifier as the checkpoint's acceptance rule

This wires `pq-fri-verify` into the bridge's CKB-side **checkpoint** logic, so the post-quantum proof *is* the
acceptance gate — replacing the BLS Mithril certificate of `spike/light-client-cell/{cert-verify,advance-cert}`.
It is the integration step: not a standalone verifier demo, but the verifier as the checkpoint transition rule.

## What it is

`ckbvm/src/checkpoint_main.rs` — a CKB **type script** on the checkpoint cell. Same 48-byte state as the
existing `advance-cert` (`epoch:u64 ‖ chain_root:32 ‖ total_difficulty:u64`), same transition shape, but the
BLS cert check is replaced by a **checkpoint-bound post-quantum proof** check:

| rule | check | exit on failure |
|---|---|---|
| genesis | no input ⇒ output == trusted genesis | 20 |
| monotone epoch | `out_epoch == in_epoch + 1` | 21 |
| **heaviest chain** | `out_total > in_total` (strict) | 22 |
| **post-quantum proof** | `verify_q_zc_seeded(out_state, witness_proof)` | 20 |

## Statement binding — how the proof is tied to *this* checkpoint

A low-degree/STARK proof on its own says nothing about *which* checkpoint it attests. The binding is via the
Fiat–Shamir transcript: `prove_q_seeded` / `verify_q_zc_seeded` (`core::ext`) **seed the transcript with the
checkpoint state** before deriving any challenge. So a proof is valid *only* for the exact 48-byte output
state it was made for — change any byte of the new checkpoint (chain_root, total, epoch) and the derived
challenges/positions change and the proof is rejected. The script seeds with the actual output cell data, so
the proof is bound to the datum the transaction is trying to write.

Host binding test (`host/src/bin/checkpoint`): a proof bound to `cp_out` **accepts for `cp_out`** and
**rejects for `cp_in`, for a tampered `cp_out`, and unbound** — confirmed.

## Demonstrated end-to-end (ckb-debugger mock transaction)

`scripts/gen_checkpoint_tx.py` builds a real advance transaction (input checkpoint cell → output checkpoint
cell, both carrying the type script; proof in the input witness):

```
(cd host && cargo run --release --bin checkpoint)   # generates the bound proof + in/out fixtures
python3 scripts/gen_checkpoint_tx.py bin/checkpoint.bin \
    fixtures/checkpoint_proof.bin fixtures/checkpoint_in.bin fixtures/checkpoint_out.bin > tx.json
ckb-debugger --tx-file tx.json --cell-index 0 --cell-type input --script-group-type type
```

| transaction | result | cycles |
|---|---|---|
| **valid advance** (epoch 7→8, heavier, bound proof) | **accept (0)** | 116.5 M |
| lighter chain (total ≤ previous) | reject (22) | — |
| non-monotone epoch (8→9) | reject (21) | — |
| tampered checkpoint datum (chain_root bit flipped) | reject (20) | — |

So the checkpoint **advances only** when the new state is strictly heavier, epoch-monotone, and accompanied by
a valid post-quantum proof bound to that exact new state — the verifier is the acceptance rule, end to end.

## The proof now attests the REAL transition — a cumulative-difficulty STARK AIR

The `checkpoint` gate above binds a proof to the checkpoint, but the proof's *internal* statement was a
placeholder low-degree test. `core::consensus` closes that: a real **two-column STARK AIR** that proves the
genuine `total_difficulty` transition —

```
acc(0) = total_old ;  acc(i+1) = acc(i) + work(i) ;  acc(nt-1) = total_new
```

— over a chain of `nt` blocks (columns `acc` = running cumulative work, `work` = per-block work; boundary +
transition constraints → composition polynomial → FRI). Host battery **6/6**: a valid transition accepts;
wrong `total_new`, broken accumulation, tampered acc/work openings, wrong `total_old` all reject.

`checkpoint_consensus_main.rs` is the upgraded gate: it verifies this AIR **and** requires the proof's proven
transition to equal the checkpoint's, `proof.total_old == in_total && proof.total_new == out_total`. So the
checkpoint advances only when a STARK proves the new total_difficulty is the correct cumulative sum from the
old one — the actual consensus quantity — bound to this exact checkpoint.

Demonstrated under a ckb-debugger advance transaction (`scripts/gen_checkpoint_tx.py` with
`bin/checkpoint_consensus.bin` + `fixtures/consensus_cp_*`):

| transaction | result | cycles |
|---|---|---|
| **valid advance** (proof attests in_total → out_total) | **accept (0)** | **52.9 M** |
| totals mismatch (datum total ≠ proven total_new) | reject (23) | — |
| tampered checkpoint datum (chain_root) | reject (20) | — |
| lighter chain | reject (22) | — |

Standalone, the consensus AIR verifies in CKB-VM at **52.8 M cycles** (nt=1024, base field, 40 queries) —
valid accepted / tampered (broken accumulation) rejected (3.1 M).

## Scope / honesty

### The full gate: quantum-secure AND real-statement, composed (`checkpoint_consensus_q`)

The two upgrades — real statement (`checkpoint_consensus`, the difficulty AIR) and quantum-secure params
(`checkpoint`, quartic F_p⁴ FRI) — compose into **one** gate. `core::consensus::{prove_cum_q_seeded,
verify_cum_q_seeded}` run the cumulative-difficulty STARK's composition polynomial through the **quartic
F_p⁴ FRI** (grinding + 100 queries) instead of the base FRI — the FRI engine is shared (`ext::prove_fri`/
`verify_fri`, transcript-threaded), only the field/params differ. The layer-0 openings are `(CP, 0)` in
F_p⁴; the verifier checks the base part equals the recomputed composition and the extension part is zero.

`checkpoint_consensus_q_main.rs` gates on it: the checkpoint advances only when a proof that is **both**
quantum-secure **and** attests the real `total_difficulty` transition (`proof.total_old==in_total &&
proof.total_new==out_total`), bound to this checkpoint, is present. Demonstrated end-to-end:

| transaction (composed gate) | result | cycles |
|---|---|---|
| **valid advance** (F_p⁴ + 24-bit PoW + 100 q, attests in_total→out_total) | **accept (0)** | **133.6 M** |
| totals mismatch | reject (23) | — |
| tampered checkpoint datum | reject (20) | — |
| lighter chain | reject (22) | — |

So a single 625 KB proof carries the ≥100-bit-quantum-margin security *and* the genuine difficulty-transition
statement, and the checkpoint script enforces both. (`checkpoint_consensus`, base-field/40-query, remains as
the simpler real-statement demo.)

What still requires hashing-in-circuit — and is therefore the zkVM's job, **not** an AIR's — is **per-block
PoW validity** (Eaglesong meeting target, parent linkage) and the **`chain_root` MMR**. That is exactly what
`spike/sp1-ckb` proves for real (SP1 header-chain). So the end-to-end split is: a zkVM proves each block's PoW
+ linkage and emits the per-block works; this AIR proves the total_difficulty is their correct cumulative sum;
the checkpoint script gates on it. The thread-token uniqueness (one-shot genesis outpoint, single thread
token) is enforced as in `advance-cert`/`ckbcert.ak`; here we run the type-script group, so input→output
continuity is by the group itself. This is a mock-transaction demonstration under ckb-debugger, not a
live-network deployment or audit.
