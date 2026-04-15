# Live replay: the deployed verifier re-executed on a REAL Pudge leap (no mock)

`replay_live_leap.py` resolves a real CKB-testnet (Pudge) transaction into a `ckb-debugger`
mock-tx by fetching **every** referenced cell from the live RPC — the inputs, the cell-deps,
and the members of any `dep_group` — then the **deployed** `bound_asset_unified` verifier
binary is run over it inside the real CKB-VM. Nothing here is synthetic: real tx, real cells,
real witness (the 1225-byte Mithril proof), real binary.

## What was run

```
python3 replay_live_leap.py 0x0318d35f677a2608e85f673f14818852f0f0e45c1da30011f6f3557e410fe667 > mock.json
ckb-debugger --tx-file mock.json --cell-type output --cell-index 0 --script-group-type type
```

## Result

```
Run result: 0
All cycles: 263741 (257.6K)
```

Resolved from the live chain: **1** input, **5** cell-deps (the type-script code cell + a
dep-group expanded to its members), witness[0] = **1225 bytes** (the real Mithril cert).
The bound cell:

```
seal_txid : 0x83dd51d2f3ae6c6529a2f6feda2d85d1a27efa5bfafc6a34c6c595d203f25e15
seal_idx  : 0
state     : "bound-asset:demo:v1"   (19 bytes, ASCII)
```

## What this closes — and what it does not

- ✅ **Verifier half, on real data.** The exact deployed `bound_asset_unified` binary
  re-verifies a genuine on-chain Pudge leap (Mithril cert + commitment + checkpoint dep),
  exit 0, in the real VM. The upstream Mithril cert was already proven on live Pudge; this
  shows the on-chain verifier accepting it locally, end to end, with no mock substitution.

- ⚠️ **Guard + verifier financial co-run is still pending an operational leap.** This live
  genesis cell carries the **demo** state (`bound-asset:demo:v1`), not the financial layout
  the leap-mint guard parses (`amount(16 LE) ‖ recipient(32)`). Running the guard *and* the
  verifier together on one tx (README §5 item 7) needs a freshly-minted **financial-state**
  leap produced by the operational pipeline (signing keys + Mithril snapshot). The guard
  itself is already proven against that exact layout in the real VM (6/6, `tests/guard.rs`);
  what remains is wiring a live leap that writes the financial state, then co-running both
  scripts on it. That step requires operational keys, not more code.

**Honest status:** the verifier now demonstrably runs on real on-chain data; the financial
guard runs on the real layout in-VM; the only un-closed gap is a single live tx that is both
*financial-shaped* and *guard+verifier-gated*, which is an operations/keys task, not a build
task — and third-party audit before any real value.
