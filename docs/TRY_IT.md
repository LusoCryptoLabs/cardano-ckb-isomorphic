# Try it - the Chiral testnet pilot

A hands-on walkthrough for a guided tester. You sign every step with your own wallets; the
relayer only proves and pays its own fees. Testnet only (CKB Pudge + Cardano preview), unaudited,
no real value - tokens are minted and burned in a closed loop.

> This is the runnable companion to the README. For what Chiral is, see the
> [README](../README.md). For how to host the pilot, see [`deploy/PILOT_DEPLOY.md`](../deploy/PILOT_DEPLOY.md).

---

## 1. Get the link

The pilot is invite-only - the operator hands you a link of the form:

```
http://<host>:8799/?t=<access-token>
```

Open it in a normal browser. The page lifts the `?t=…` token into local storage and sends it on every
heavy call, so you only need it once. (Don't share the link - the token gates a heavy prover.)

> Wallet note: the pilot currently serves plain HTTP on a bare IP (no TLS yet). Most browser
> wallets work, but a few that require a *secure context* (e.g. passkey-based flows) may refuse to
> connect. If a wallet won't connect, tell the operator - they can switch the pilot to HTTPS.

## 2. What you need (two wallets, two faucets)

| Chain | Wallet | Testnet | Faucet |
|---|---|---|---|
| CKB | JoyID (or any CKB wallet ccc supports) | Pudge | <https://faucet.nervos.org/> (sign in with GitHub) |
| Cardano | Lace or Eternl | Preview | <https://docs.cardano.org/cardano-testnets/tools/faucet> (select Preview) |

- On CKB Pudge, you need one funding cell of ≥ ~365 CKB - see the funding rule below.
- On Cardano preview, a few preview ADA is enough (transaction fees + collateral).

### The one funding rule that matters (CKB side)

The forward proof is keyed to a canonical single-input lock, so you must fund the CKB lock from
ONE cell of ≥ ~365 CKB. A fresh faucet payout is a single cell and qualifies. If your wallet is
fragmented into many small cells, the dApp returns a clear *"consolidate / use a fresh faucet cell"*
error instead of locking. (Minimum lock is 300 CKB; the extra covers the receipt's occupied bytes +
fee + change.)

## 3. The forward round trip - CKB → Cardano (χCKB)

You lock CKB and get a wrapped χCKB on Cardano; burning it releases your CKB back.

1. Connect your CKB (JoyID) and Cardano (Lace/Eternl) wallets in the page.
2. Lock - enter an amount (≥ 300 CKB) and start the leap. Sign in JoyID. This creates a
   conservation-safe, burn-gated receipt on Pudge.
3. Prove - the relayer runs the Groth16 prover over your lock. The first proof takes ~2 minutes
   (a ~114-second cold prove on the shared pilot box) - the banner shows *"cold · first proof ~min"*.
   This is normal, not a hang. The queue indicator shows your position if others are ahead.
4. Mint χCKB - sign the Cardano mint in your wallet. The minting policy enforces *quantity ==
   the exact CKB you locked*, so mint = lock by construction.
5. Burn χCKB - sign the burn in your Cardano wallet; supply drops back toward zero.
6. Release my CKB - push-button. The dApp drives the whole keyless release (wait for the burn to
   be Mithril-certified → advance the light-client if needed → publish the checkpoint → insert the
   replay-once nullifier → release to your CKB address). If the burn isn't certified yet it says
   *"not certified yet - retry shortly"*; the Mithril aggregator certifies on a schedule, so this leg
   can take ~7–10 minutes. That's a latency floor, not a bug.

## 4. The reverse round trip - Cardano → CKB (χADA)

The mirror direction: lock ADA, get χADA (an xUDT) on CKB; burn it to get your ADA back.

1. Lock ADA into the escrow and mint χADA on CKB (sign on both sides).
2. Burn & return - burn the χADA on CKB; the relayer proves the burn and releases your ADA from
   the Cardano escrow. This leg is also Mithril/checkpoint-gated (~7–10 min).

> The χADA escrow uses a placeholder return verifier capped at a small demo amount - keep ADA test
> amounts tiny.

## 5. Verify the live deployment yourself

Don't take the operator's word for it - the config is public on the pilot host:

```sh
curl -s http://<host>:8799/api/health # { "ready": true, ... }
curl -s http://<host>:8799/api/bridge/config # burnGated.policyId
```

As of 2026-06, the live forward χCKB mint policy is
`5b4f5525a155fd86757bb3ba20da6e2ef66bcfb72e8853ef31bcf268`. Treat
[`/api/bridge/config`](../dapp/server.mjs) as the source of truth - if it ever differs, the API wins,
not this file. Older policy ids (`4cd5c378`, `029cca60`, `08db0245`, …) are superseded and must not be
used.

## 6. Good to know

- One reverse leg at a time. Releases and returns touch shared on-chain singletons (registry /
  light-client checkpoint), so the relayer serializes them. If yours is queued, wait - it's not stuck.
- Nothing has value. Everything is testnet; χCKB/χADA are minted and burned in a closed loop.
- Stuck? Re-open the same link (your token persists), check `/api/health`, and tell the operator
  the tx hash. Forward steps 1–5 are fully in your browser; the release/return legs run on the host.
