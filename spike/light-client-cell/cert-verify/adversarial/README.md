# Phase-5 adversarial test suite — Cardano→CKB light client

Soundness-regression evidence for the `cert-verify` Mithril light client. It drives the
three verifier modes (`standalone`, `deploy`/TxSetCert, `advance`) under `ckb-debugger`
with mock transactions and asserts that **every forged / replayed / equivocating /
reorg'd input is rejected with the exact expected script error code**, and that the
canonical inputs are accepted.

This is the offensive counterpart to the differential test
(`spike/cardano-to-ckb-zk/mithril_verify/difftest_results.txt`, 25/25 live certs vs
`mithril-stm`): the difftest proves *valid* certs are accepted; this proves *invalid* ones
are rejected, and that the chain-integrity guards (genesis pinning, epoch/avk binding,
avk-source type binding) actually fire.

## Run

```
./build.sh          # optional — prebuilt binaries are checked into ./bin
python3 suite.py    # 23/23 scenarios; exit 0 on full pass
```

Requires `ckb-debugger` on PATH (or `CKB_DEBUGGER=/path`). No network, no node.

## Files

| file | role |
|---|---|
| `suite.py`      | the 23 scenarios (batteries A/B/C) |
| `harness.py`    | builds a `ckb-debugger` MockTransaction and parses the script return code |
| `witness.py`    | parses the `MWIT` witness layout so mutations hit exact fields |
| `fixtures/`     | real Mithril cert witnesses: `cert_witness.bin` (MSD epoch-transition cert), `witness_1319/1320.bin` (advance-chain certs) |
| `bin/`          | prebuilt stripped verifiers; `cv_advance.bin` is the canonical `0xe877a80…` |
| `RESULTS.txt`   | captured output |

## What each battery proves

**A — forged cert (standalone).** A real cert witness is mutated one field at a time;
each tamper must make `verify()` fail (exit `20`), and malformed encodings must fail
closed:

- A1 BLS signature `sigma`, A2 verification key `mvk`, A3 signer stake, A4
  `signed_message` (M1), A5 `avk_root` (Merkle/BLS), A6 Merkle batch value, A7 quorum
  threshold `k` inflated above available sigs → all `20`.
- A8 **equivocation**: forging a different `next_aggregate_verification_key` → `20`,
  because the next-avk is inside the M1-signed protocol message, so you cannot publish a
  conflicting next key under the same signature.
- A9 truncated witness → fail-closed VM abort; A10 wrong magic → no witness found (`1`).

**B — chain integrity (advance mode).** Genesis pinning + epoch/avk binding + monotonic
roll-forward:

- B1 a **fake genesis** (attacker-chosen avk) is rejected (`7`); B2 the one canonical
  pinned genesis is accepted (`0`); B3 a real `1319→1320` advance is accepted (`0`).
- B4 **replay** a cert against the wrong-epoch checkpoint → `10`; B5 doctored input avk →
  `11`; B6 **reorg**/epoch-skip output → `5`; B7 attacker-chosen output avk (not the
  cert's signed next-avk) → `5`; B8 a forged cert inside an advance → `20`.

**C — avk-source binding (deploy/TxSetCert mode).** The avk a tx-set checkpoint trusts must
come from a checkpoint cell carrying the **canonical advance-verifier type**
(`type-hash 0x59efd99d…`), not any 48-byte cell:

- C1 an untyped 48-byte cell is not trusted (`3`); C2 a wrong-type cell is not trusted
  (`3`); C3 a correctly-typed checkpoint whose avk ≠ the cert's avk is rejected (`6`);
  C4 a correctly-typed, avk-matching checkpoint passes the binding and reaches the
  tx-root gate (`14` for this MSD cert, which carries no `cardano_transactions_merkle_root`).

Error codes are the verifier's own returns in `../src/main.rs`.
