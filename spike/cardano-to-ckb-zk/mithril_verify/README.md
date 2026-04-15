# Mithril verification of the Cardano burn (reverse-leg trust anchor) — WORKING

Verifies, with the official mithril crates, that our Cardano burn `6608c4c8…` is certified by Mithril
(a BLS12-381 STM threshold multi-signature of Cardano stake). This is the trustless reverse-leg anchor
and the exact computation STARK-Mithril arithmetizes.

## Result (real data, preview)
```
tx-inclusion proof verified; cert 37e9c576…
STM_MULTISIG_VERIFIED true
cert 37e9c576… epoch 1321 params k=1944 m=16948 phi_f=0.2
certified_transactions ["6608c4c828ceec5bb94c0973aeb41f5e04a85225a06edd90874b09d20515a800"]
```
So: (1) our burn's tx-inclusion Merkle proof verifies, and (2) the certificate's BLS-STM aggregate
multi-signature verifies against the epoch-1321 stake AVK + params — i.e. >threshold Cardano stake signed it.

## Working build (the dep-drift fix)
The published crates mis-resolve transitive deps; use the git workspace at a release tag (internally
consistent) + the `rustls` TLS feature (`num-integer-backend` is already default, avoiding `rug`):
```
mithril-client = { git = "…/mithril", tag = "2617.0", features = ["rustls"] }
mithril-common = { git = "…/mithril", tag = "2617.0" }
```
`src/main.rs`: fetch proof → `proofs.verify()` (tx inclusion) → message→`Certificate` → extract the
`MultiSignature` → `msig.verify(signed_message, avk, params)` (the single-cert STM check, fast — no
chain-to-genesis walk). `signed_message.py` separately reproduces relation M1 (the Sha256 signed message).

NOTE: the message carries `aggregate_verification_key_snark` — Mithril is upstreaming SNARK-friendly
certificates (`future_snark`), i.e. STARK-Mithril is converging with their roadmap.
