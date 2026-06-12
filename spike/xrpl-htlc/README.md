# XRPL over HTLC: a cheap proof of bridge Mode B

This spike proves that a chain with **no smart contracts** (the XRP Ledger) can still join the Chiral bridge,
as an **atomic-swap leg** rather than a verify-and-mint leg. It validates the multi-mode thesis: "add a chain"
is a routing decision, and a non-programmable chain routes to HTLC (Mode B), needing no light client and no SNARK.

## The mechanism

One shared secret `s`, one hashlock `H = SHA256(s)`, used unchanged on both chains:

- **XRPL side (live, native):** an `EscrowCreate` with `Condition = PreimageSha256(H)` plus `CancelAfter` (a
  timelock). The escrow can only be finished by presenting the preimage as the `Fulfillment`; finishing it
  reveals `s` on the public ledger. XRPL gives us a hashlock and a timelock natively, which is exactly an HTLC.
- **CKB side (`htlc_lock`):** a lock whose args are `H(32) || recipient_lock_hash(32) || sender_lock_hash(32)
  || timeout(8)`. It unlocks two ways: CLAIM (the witness carries the preimage, `SHA256(preimage) == H`, and an
  output pays the recipient) or REFUND (the input `since` >= timeout and an output pays the sender). Binding the
  funds to recipient/sender means that revealing the preimage never lets a third party redirect the value.

Because both sides key on the same `SHA256(s)`, revealing `s` to claim one side exposes it for the other. That
is the atomicity: no custody, no trusted relayer for safety, only liveness (the standard HTLC property).

## The swap choreography (Alice has XRP, wants CKB; Bob has CKB, wants XRP)

1. Alice picks `s`, computes `H`, and locks XRP to Bob on XRPL under `Condition = PreimageSha256(H)`,
   `CancelAfter = T2`.
2. Bob locks CKB to Alice in an `htlc_lock` cell under the same `H`, with `timeout = T1 < T2`.
3. Alice claims the CKB by revealing `s` (the CKB CLAIM path). `s` is now public on CKB.
4. Bob reads `s` and finishes the XRPL escrow with `Fulfillment = s` before `T2`, receiving the XRP.
5. If either party stalls, the timelocks refund: Bob reclaims CKB after `T1`, Alice reclaims XRP after `T2`.
   The ordering `T1 < T2` guarantees the party who moves second still has time.

## What was actually run

- **XRPL leg, LIVE on testnet** (`xrpl_htlc_demo.mjs`): funded two faucet wallets, `EscrowCreate` locked 10 XRP
  under `H`, `EscrowFinish` released it only by revealing `s`. Both `tesSUCCESS`. Bob's balance went 100 -> 110
  XRP. Example finish tx: `6D6CCA92BD337188A32925C362728589A7946D47AD48DCC7428FA275188BA2B2`
  (https://testnet.xrpl.org/transactions/6D6CCA92BD337188A32925C362728589A7946D47AD48DCC7428FA275188BA2B2),
  with `H = 200DE703657DA41E834D9000B045D06E4072081DD0BDA148BF3915F4CC87EABF`.
- **CKB leg, in ckb-debugger** (`htlc_lock.rs`, built in WSL; `build_ckb_mock.mjs` emits the mocks against the
  SAME `H`): CLAIM `Run result: 0`, REFUND `Run result: 0`, BADCLAIM (wrong preimage, no timelock)
  `Run result: 2` (rejected).
- **FULLY LIVE swap, both real chains** (`live_swap.mjs`): `htlc_lock` is now DEPLOYED on Pudge (codeHash
  `0xa08d3763...`, dep tx `0x74c21c0f...`). One run: Alice locked 10 XRP under `H` on XRPL (`EF71F9DE...`),
  200 CKB locked in a real `htlc_lock` cell (`0x037dc1c6...:0`), claimed ON-CHAIN by revealing `s`
  (`0x12d71ef6...`), the relay read `s` from that CKB claim witness and finished the XRPL escrow
  (`3CF7E943...`), Bob 100 -> 109.99 XRP. The same secret settled both real chains, no party holding funds.
- **The relay** (`swap_relay.mjs`): the same choreography with the CKB side in ckb-debugger (handy when you do
  not want to spend the on-chain code-cell capacity); `live_swap.mjs` is the on-chain version.

## How to run

```
# XRPL leg (live testnet, free faucet)
cd spike/xrpl-htlc && npm install && node xrpl_htlc_demo.mjs

# CKB leg
wsl: cd spike/burn-gated-unlock && RUSTFLAGS="-C target-feature=-a,+forced-atomics" cargo build --release --bin htlc_lock
node build_ckb_mock.mjs    # writes claim.json, refund.json, badclaim.json under the same H
wsl: ckb-debugger --tx-file spike/xrpl-htlc/claim.json   --script-group-type lock --cell-type input --cell-index 0   # 0
     ckb-debugger --tx-file spike/xrpl-htlc/refund.json  --script-group-type lock --cell-type input --cell-index 0   # 0
     ckb-debugger --tx-file spike/xrpl-htlc/badclaim.json --script-group-type lock --cell-type input --cell-index 0  # 2
```

## Trust model and where this sits

Mode B is trustless for safety (atomic: you either swap or refund) but liveness-based and liquidity-based: it
needs a counterparty with the opposite asset, and a watcher to reveal the preimage on the second chain. There
is no wrapped asset and no consensus verification, so XRPL contributes nothing to verify on CKB and CKB
contributes nothing to verify on XRPL. That is the honest ceiling for a chain that cannot host a verifier.

This contrasts with the bridge's Mode A (verify-and-mint), where the destination verifies the source's finality
(Mithril cert in CKB-VM, or a Groth16 proof of CKB on Cardano) and mints a wrapped asset. Stellar (Soroban) and
Solana (alt_bn128) can host a verifier and so can join Mode A; XRPL cannot, and joins here via Mode B.

## How to run

```
cd spike/xrpl-htlc && npm install
node live_swap.mjs     # FULLY LIVE: deploys htlc_lock (first run), locks + claims on Pudge, settles XRPL
node swap_relay.mjs    # same choreography but CKB claim in ckb-debugger (no on-chain code-cell spend)
```

## Next steps

- The mirror direction (watch the CKB claim on Pudge, submit the XRPL `EscrowFinish`) as a long-running
  daemon, with the timelock-ordering safety checks (`T1 < T2`) enforced before locking the second leg.
- Generalize to a swap-leg interface so XRPL, Bitcoin, and Lightning/Fiber share one Mode B implementation.
