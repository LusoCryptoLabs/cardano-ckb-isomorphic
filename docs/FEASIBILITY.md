# FEASIBILITY — can a CKB script verify a Cardano light-client proof?

> **✅ RESOLVED (2026-06) — verdict confirmed and superseded by live results.** This is the
> original Phase-1 feasibility analysis, kept as the audit trail. Everything it left open (§5) was
> since proven: a real Mithril cert verifies **bit-exactly in CKB-VM** at ~134–146M cycles, the
> light-client cell (`AdvanceCert`) runs **live on Pudge**, and the tx-membership proof binds a real
> anchor spend. For the current state see `CHIRAL_STATUS.md`, `LIVE_STATUS.md`, `CHIRAL_READINESS.md`.
> Read below as "what we knew going in," not current status.
>
> **Phase-1 spike (gate for `DESIGN.md`).** Branch: `spike/cardano-lightclient-feasibility`
> — deliberately **not on `main`**. The single load-bearing assumption of the whole
> isomorphic-binding design is tested here: *a CKB script can verify a Cardano light-client
> proof that is (a) granular enough to prove a specific anchor UTxO/spend, (b) fresh enough
> for usable latency, and (c) cheap enough to fit the CKB VM budget.*
>
> **Verdict: GO**, with latency (b) as the design caveat — not a blocker. Evidence below.
> Merge to `main` only after review of the (b) caveat and the Phase-1.5 confirmation in §5.

## Summary

| Sub-question | Verdict | Basis |
|---|---|---|
| (a) Granularity — prove a *specific* anchor spend | 🟢 GREEN | Mithril certifies the **Cardano transaction set** with a **Merkle proof of membership** for a subset — tx-level inclusion. |
| (b) Freshness — usable latency | 🟡 YELLOW | Signer cadence ~10 min; tx certification historically immutable-file-bound (lag from tip); active work pushing to near-tip. Fine for a settlement-delayed bridge; a tunable, improving parameter. |
| (c) Cost — fits the CKB VM budget | 🟢 GREEN (measured) | **42.7M cycles/pairing, 24.8K/ G1-add** on CKB-VM ⇒ a Mithril single-cert verify ≈ **~134M cycles ≈ 3.8% of a 3.5e9 block** at live mainnet `k=1944`. |

## (a) Granularity — GREEN

Mithril now certifies the **Cardano transaction set** (not just stake distribution / full
snapshots): the certified set is stored in a Merkle tree, and the aggregator exposes
**proof-of-membership** routes so a client can obtain a cryptographic proof that a *specific
subset of transactions* is in the certified chain. That is exactly the granularity the
binding needs: prove that the transaction which **spends the anchor UTxO** is in Cardano's
certified history.

- IOG: Mithril enables "certification of transactions in layer-2 solutions (bridges, state
  channels, rollups, …)" and light-wallet account/balance certification.
- `mithril-stm` / `mithril-client` expose transaction-membership proofs; aggregator REST API
  has the proof routes.

**Caveat to close in design:** tx-inclusion proves *the spend tx happened*; the binding
protocol (DESIGN §3.2) must map "anchor-spend tx certified" → "this anchor UTxO consumed
with this commitment." That's protocol glue, not a Mithril limitation.

## (b) Freshness — YELLOW (workable, latency-bound)

- Mithril **signers emit a new signature ~every 10 minutes**; registration every ~5 days.
- **Transaction certification historically rides immutable-file boundaries**, which lags the
  chain tip (the known high-latency constraint). IOG has an active workstream (a
  **chainsync-based importer**, mithril#1701) to certify transactions **near the tip**,
  removing that limit.

For an Chiral binding protocol this is acceptable: a leap-in already implies a settlement delay
(you wait for source-chain finality regardless), and Mithril's cadence (minutes) is the same
order as the optimistic challenge window in the sibling bridge. **Latency is a tunable UX/
safety parameter to design around, and it is actively shrinking** — not a feasibility blocker.
This is the item to keep watching as Mithril ships low-latency tx certification.

## (c) Cost — GREEN (measured on CKB-VM)

Measured with the sibling repo's CKB toolchain (`ckb-testtool` 0.13, `rustc` 1.94.1,
target `riscv64imac-unknown-none-elf`, `opt-level="z"`+lto, pure-Rust `bls12_381` v0.8).
Method: a CKB script binary (`spike/ckb-vm-bls-bench/bls_bench.rs`) runs `n_pair` pairings +
`n_add` G1 additions; cost per op = delta across two runs (cancels fixed VM/startup overhead).

```
per BLS12-381 pairing : 42,701,710 cycles
per G1 addition       :     24,820 cycles
(baseline ML-DSA-44 verify, same harness: 4,390,000 cycles)
CKB mainnet max_block_cycles: 3,500,000,000
```

A Mithril **STM single-certificate verify** over a *single message* (the snapshot Merkle
root) collapses, with PoP-registered keys, to **~2 pairings + ~k G1 additions** (sum the `k`
winning signers' keys) + `k` cheap eligibility hashes + a batched Merkle check. At the
**live mainnet quorum `k=1944`** (`m=16948`, `phi_f=0.2`, from the release-mainnet aggregator):

```
2 pairings + 1944 G1-adds  ≈ 133.6M cycles  ≈ 3.8% of a 3.5e9 block
```

Even with a **5× conservative multiplier** for hashing, the batched Merkle proof, hash-to-curve
of the message, and any multi-message handling, that is **~670M cycles ≈ ~19% of a block** —
still comfortably within budget. Headroom is large.

## (d) Testnet availability

Mithril runs on Cardano **preview** and **preprod** (and mainnet), so the whole spike chain
— pull a real cert + tx-membership proof from a testnet aggregator, verify it in a CKB
script — can be exercised end-to-end on test networks before any mainnet work.

## 5. What is NOT yet proven (honest scope of this spike)

This spike measured the **primitive costs** and **modeled** the STM verify; it did **not**
implement the full `mithril-stm` verify in-script. Before merging the design to `main`,
Phase-1.5 should:

1. **Implement the real `mithril-stm` aggregate verify in a CKB script** against a genuine
   testnet certificate, and read back the true end-to-end cycle count (confirm the
   "2 pairings + k adds" model, including eligibility hashing, the batched Merkle proof, and
   whether any path needs per-signature pairings rather than aggregation).
2. **Confirm the transaction-membership proof format** and that it binds to an anchor-UTxO
   spend (close the (a) caveat).
3. **Measure hash-to-curve** (one-time, constant — expected negligible vs. the k term).
4. Track Mithril's **low-latency tx certification** (#1701) for the (b) parameter.

None of these threaten the verdict; they tighten the numbers and the protocol glue.

## Reproduce

`spike/ckb-vm-bls-bench/bls_bench.rs` is a CKB script bin. To measure, drop it into a CKB
script workspace (e.g. the sibling `cardano-ckb-bridge/ckb/scripts`, add
`bls12_381 = { version = "0.8", default-features = false, features = ["groups","pairings","alloc"] }`
and a `[[bin]]`), build for `riscv64imac-unknown-none-elf`, and run it under `ckb-testtool`
at two `(n_pair, n_add)` settings, reading back `verify_tx` cycles. See `RESULTS.txt` for the
exact numbers obtained.

## Sources
- Mithril — transaction certification / proof of membership: <https://mithril.network/doc/>,
  <https://iohk.io/blog/posts/2025/05/19/mithril-powering-lightweight-access-to-the-cardano-blockchain/>,
  mithril#1393 (certify UTxO/transactions set).
- STM / BLS12-381 (blst), batch verification: <https://docs.rs/mithril-stm>,
  Chaidos & Kiayias, *Mithril: Stake-based Threshold Multisignatures* (eprint 2021/916).
- Signing cadence + low-latency tx certification: mithril#1701, Mithril signer docs.
- Live mainnet params (`k=1944, m=16948, phi_f=0.2`): release-mainnet aggregator
  `/epoch-settings`.
- Cost: measured here (`spike/ckb-vm-bls-bench/`), CKB `max_block_cycles` = 3.5e9.
