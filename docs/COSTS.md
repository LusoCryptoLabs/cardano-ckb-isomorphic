# Costs — measured, with the amortized per-transfer model

> Real figures from the live testnet runs + benchmarked CKB-VM cycles.

## Per-transfer cost for a regular user (the number that matters)

| | Amount | Note |
|---|---|---|
| Cardano fee | **~0.24 ADA** | measured (binding-lock spend `a98b6636`); leap-in was 0.21 ADA |
| CKB fee | **~0.02–0.05 CKB** | size-based; the per-transfer proof rides in the **witness** (a few KB) |
| CKB bound-cell deposit | **~114 CKB** | measured; **refundable** on leap-out (like Cardano min-ADA) |

**≈ a quarter-ADA + a few cents of CKB per transfer, plus a refundable ~114 CKB while bound.**

## What the user does NOT pay
- The **~45,000 CKB** verifier script is an **operator one-time** cost, **reclaimable** (we reclaimed
  it live: deploy tx `0x9eb56c3b`), and **shared** by every bound cell (a `cellDep`). Not per-user.
- The **light-client checkpoint advance** (~2.46e9 cycles naive ≈ 70% of a block; ~5% optimized) is
  paid **per Mithril epoch by the relayer/operator** and **amortized over all transfers** in that
  epoch. Not per-user.

## Demo artifact vs. production model
In the earliest demo each step embedded its proof in a fresh ~45 KB code cell, so each looked like
~45k CKB. **Production model (now built + live):** deploy the verifier **once** (~45k, reclaimable)
and put the per-transfer proof in the **witness** → the per-transfer cost is the ~0.05 CKB row
above. This is the unified `BoundAsset` (`spike/phase1/`), deployed once on Pudge (`0xf8644bd3`,
code_hash `0x42f74fbc`) and referenced by every bound cell as a cellDep — see `LIVE_STATUS.md`.

## Amortized operator cost (per transfer, as volume grows)
Let `D` = one-time script deploy (~45k CKB, **reclaimable**, so ~0 long-run), `A` = light-client
advance cost per epoch, `T` = transfers per epoch.
```
operator cost / transfer ≈ A / T        (D amortizes to ~0; it's refundable capital, not spend)
```
The advance is a periodic compute tx whose ADA/CKB *fee* is small (size-based); its real "cost" is
block space (~5% optimized). At any meaningful `T`, operator cost/transfer → negligible.

## Versus the committee bridge (cardano-ckb-bridge)
| | Committee bridge | Chiral binding protocol |
|---|---|---|
| User fee/transfer | ~0.4–0.5 ADA (assert+finalize) + tiny CKB | **~0.24 ADA + ~0.05 CKB** |
| Locked capital | **Bonds** (cap-derived, large; the economic security) + custody liquidity | ~114 CKB/cell (refundable) + operator's reclaimable ~45k script |
| Recurring ops | **Watchtowers 24/7 + signer infra/HSM** | relayer (liveness) + free public Mithril |
| Security paid with | capital + human operations | computation + (reclaimable) storage |

**Bottom line:** both cost pennies per transfer in fees; the committee bridge's real cost is
**locked bonds + 24/7 watchtower/signer ops**, the Chiral binding protocol's is **reclaimable script
capacity + a periodic amortized verification tx** — trading recurring human/capital cost for
one-time storage + compute.
