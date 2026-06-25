# Chiral dApp - testnet testing runbook

A self-serve CKB ⇄ Cardano leap on testnet only (CKB Pudge + Cardano preview). Unaudited, no real
value. What works self-serve today, what the relayer automates, and how to host it for testers.

> Testers: the step-by-step walkthrough is [`../docs/TRY_IT.md`](../docs/TRY_IT.md). This runbook is
> the host / operator reference.

## What testers can do self-serve (works today)
1. Lock CKB on Pudge (sign in JoyID) → a conservation-safe burn-gated receipt.
2. Prove the lock (the daemon runs the Groth16 prover - ~2 min cold on the shared pilot box; the dApp
   banner shows "cold · first proof ~min" - this is expected, not a hang).
3. Mint χCKB on Cardano preview (sign in your Cardano wallet) - the policy enforces qty == the locked amount.
4. Burn χCKB on Cardano (sign in your wallet) → supply drops.

→ Steps 1–4 are fully user-signed and complete in the browser.

5. Release the locked CKB against the burn - now push-button: the dApp's "Release my CKB" button calls
   `/api/leap/release`, which drives the whole pipeline automatically (cert gate → advance the AVK light-client
   to the burn's epoch if stale → publish the LCKP at the burn root → insert the replay-once nullifier →
   keyless `bg_release` to the tester's CKB address). It's keyless on-chain (no key authorizes the receipt
   spend), but it runs on this host (the funded relayer key submits + pays fees). Until the burn is
   Mithril-certified (aggregator-scheduled) the button returns "not certified yet - retry shortly".

   Note: the tester must supply (or have locked this session) their original lock tx as the receipt to
   release. Reverse legs touch shared singletons (registry / light-client) - run them one at a time.

## What a tester needs
- JoyID (or any CKB wallet) on Pudge, funded from a single cell of ≥ ~365 CKB (a fresh faucet
  payout is one cell and qualifies; min lock 300). A fragmented wallet gets a clear "consolidate" error - the
  forward proof is keyed to a canonical single-input lock. Faucet: https://faucet.nervos.org/ (GitHub sign-in).
- A Cardano preview wallet (Lace / Eternl) with a few preview ADA (fees + collateral).
  Faucet: https://docs.cardano.org/cardano-testnets/tools/faucet (select Preview).

## Host: running the daemon
The daemon is not a generic cloud app - `prove` needs the prover toolchain (the prebuilt `relay_bind` /
`leap_bound_windowed` ELFs + python + pycardano) and releases need the funded relayer key. On Windows it runs
via the WSL `ChiralSP1` distro; on a Linux VPS it runs natively (`CHIRAL_NATIVE=1`). For the full
VPS deploy (systemd units, swap, memory caps, cold-per-prove), follow [`../deploy/PILOT_DEPLOY.md`](../deploy/PILOT_DEPLOY.md).

Quick local run:
```sh
cd dapp
npm run build # build the SPA (once, or after UI changes)
node server.mjs --port=8799
curl localhost:8799/api/health # must show { "ready": true } before onboarding testers
```

Gate it. Set `CHIRAL_ACCESS_TOKEN=<a long secret>` in the environment and hand each tester a link of the
form `http://<host>:8799/?t=<token>` - the dApp lifts the token into storage and sends it on every heavy call.
Rotate the token to revoke a cohort. Expose only to known testers (the prover is a DoS magnet - never a
public link); front it with TLS where you can:
```sh
cloudflared tunnel --url http://localhost:8799 # quick https URL to share (no domain needed)
```

## What the push-button release automates (operator / debug reference)
The "Release my CKB" button (`/api/leap/release`) now drives the whole reverse pipeline via
`relayer/onchain/release_orchestrate.mjs` - you do not run these by hand. They're kept here as the
operator/debug reference for what runs under the hood. The leg is gated on the burn being Mithril-certified
(the aggregator certifies on a schedule) and on the on-chain AVK light-client being current with the burn's
epoch. The manual equivalent, from `relayer/`:
```sh
# 1) cert witness (LCKP) + MKMapProof (receipt spend) - both return wait-certification until certified
python3 gen_cert_witness.py <BURN_TXID> onchain/bg_ctwit.json
python3 produce_witness.py <BURN_TXID> > onchain/bg_release_wit.json
# 2) if the burn's Mithril epoch > the on-chain AVK checkpoint epoch, advance the light-client one epoch
# (clone onchain/gen_advance_1332.py + advance_1332.mjs, bump the epoch numbers), then:
node onchain/advance_<EPOCH>.mjs
# 3) publish the LCKP at the burn's certified root, insert the replay-once nullifier, release (keyless)
node onchain/bg_refresh.mjs
python3 reg_null_burn.py onchain/bg_release_wit.json onchain/registry_state.json <LIVE_REGISTRY_ROOT>
# (point onchain/bg_receipt.json at the tester's receipt + onchain/boundasset_v2_state.json.registry at
# the live registry singleton first)
node onchain/bg_release.mjs
```
This is the pipeline proven live (round trip `0xcaf514b0` … `0x0bfabccc`), now automated by
`/api/leap/release` → `release_orchestrate.mjs`. The steps above are the operator/debug reference, not a
required manual procedure.

## Caveats to tell testers
- Testnet, unaudited, no real value; tokens are minted→burned in a closed loop.
- The forward leap is self-serve; getting CKB back (release) is push-button (the dApp drives the keyless
  release), but it runs on the host and waits for the burn's Mithril certification (~7–10 min).
- Shared singletons (registry / light-client checkpoint) mean reverse legs are best run one at a time.
