# Can the Cardano leg be post-quantum? — yes, via hash-based signatures (measured)

`PLUTUS_PQ_COST.md` showed a hash-based **FRI/STARK** verifier does **not** fit a Plutus transaction (~2–14×
over the per-tx budget; Plutus has no general VM and accelerates only BLS12-381). That ruled out the
*trustless light-client* on Cardano in a single tx. But it did **not** rule out a post-quantum Cardano leg —
because the bridge's Cardano side can authenticate the counterparty chain with a **certificate / signature**
(it uses Mithril BLS today), and a **hash-based signature** is a different PQ primitive whose verification is
~1,000 hashes — small enough to fit.

## Measured (`lib/wots.ak`, `aiken check`, Plutus v3)

A real **Winternitz one-time signature (WOTS+)** — the hash-only core of XMSS / SPHINCS+ — verified in Aiken
(w=16, len=67 over a 256-bit message). On-chain only **verify** runs (keygen+sign are off-chain); cost
isolated as `full round-trip − (keygen+sign)`:

| | cpu-steps | mem units |
|---|---|---|
| **WOTS+ verify (on-chain)** | **2,772,461,778** | **9,190,868** |
| Plutus per-tx budget | 10,000,000,000 | 14,000,000 |
| **share of budget** | **27.7 %** | **65.6 %** |

**It fits** — comfortably on cpu, with headroom on memory (and the Aiken implementation is naive: it uses
`list.at` (O(n²)) and intermediate lists; a tuned verify that compares each chain in place would cut the
memory materially). Contrast the hash-STARK at ~2–14× over.

## So the Cardano leg *can* be post-quantum — under the certificate model

- **Developable now:** replace Mithril's **BLS** certificate with a **hash-based** one (WOTS+/XMSS), verified
  in Plutus. **XMSS** (WOTS+ keys under a Merkle tree → many-time, stateful) adds only a ~h-hash auth path
  (~10–20 hashes) on top of the WOTS+ verify, so it also fits. This is the **post-quantum, committee/notary**
  Cardano leg — the symmetric partner of the CKB-side verifier, making **both legs post-quantum under the
  committee trust model.**
- **Caveats (honest):**
  - **One signature per tx.** A single verify already uses ~66 % of the memory budget, so a large
    *K-of-N quorum* (Mithril-style, hundreds of signers) does **not** fit one tx — it needs **signature
    aggregation** (harder for hash-based than BLS) or **splitting across txs**, or a single
    threshold/aggregated hash-based key (notary / few-signer model). SPHINCS+ (stateless, ~thousands of
    hashes) likely overflows; **XMSS (stateful) is the fit.**
  - This is the **certificate** trust model (honest-majority / notary), **not** the trustless light-client.
    The trustless Cardano leg still needs the hash-STARK → split across txs, or Cardano PQ builtins.
  - This is a feasibility **measurement**, not a deployed, parameter-hardened, audited signature scheme.

## Bottom line

The Cardano leg is **not categorically blocked**: a post-quantum verifier **is developable** — a hash-based
signature (WOTS+/XMSS) fits a Plutus tx (measured ~28 % cpu / ~66 % mem). So **both legs can be post-quantum
under the committee/certificate model** (the bridge's current trust model, with BLS → hash-based). What
remains genuinely hard / out of scope is the *trustless* Cardano leg (hash-STARK in Plutus — needs tx-chaining
or protocol builtins) and the chains' own anchor signatures. The earlier "Cardano leg infeasible" applies to
the hash-STARK, **not** to a PQ certificate.
