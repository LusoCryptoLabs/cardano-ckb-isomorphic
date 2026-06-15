# Chiral Leap, operator demo UI

A minimal dashboard for the v2 ownership-toggle leap (CkbOwned ⇄ CardanoBound, both ways). This is the
**operator** demo: the relayer's own keys (`leap_orchestrator.mjs`) do the work; the UI observes and (Phase 2)
triggers it. No wallets, no user self-custody, no value moved by the UI. Testnet, unaudited.

## Run

```
cd relayer/onchain
node demo_server.mjs --port=8788      # needs the operator env: ~/.chiral keys + WSL ChiralSP1 (for cardano_status.py)
# open http://localhost:8788
```

The dashboard shows: the current side (CkbOwned/CardanoBound) + next leg, the bound cell + seal, CKB/Cardano
balances, the registry root, parked checkpoints, funding health, and the recent-leaps log with explorer links.
It polls `/api/leap/status` every 12s; the server refreshes that snapshot in the background every 30s (one
`leap_orchestrator.mjs status --json` run, ~30s of chain queries, so it is cached, not per-request).

## Endpoints (server: `demo_server.mjs`, stdlib node http)

| endpoint | source |
|---|---|
| `GET /` | the dashboard (`demo_ui.html`) |
| `GET /api/config` | deployed code hashes + explorer bases + side (state files) |
| `GET /api/leap/status` | cached live both-chain snapshot (`leap_orchestrator.mjs status --json`) |
| `GET /api/leap/history` | recent legs (`leap_log.jsonl`), newest first |

## Roadmap

- **Phase 1 (done): read-only dashboard.** Live state + history, no actions.
- **Phase 2: drive a leap.** An async job runner that spawns `leap_orchestrator.mjs leg`/`toggle` as a
  background child, parses its structured log into steps (build → submit → await-cert → cardano-tx →
  ckb-confirm), and exposes `POST /api/leap/{leg,toggle}` + `GET /api/leap/jobs/:id`; the UI's two buttons
  (currently disabled) drive it with a live step tracker.
- **Phase 3: polish.** Error surfacing, the optional Groth16 χCKB value-mint tab.

Not in scope (that is the post-audit self-custody dApp): wallet-connect, user signing, the `/submit` finalize
path, real value.
