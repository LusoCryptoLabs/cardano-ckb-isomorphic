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
| `POST /api/leap/leg` `{recipient?,verify?}` | start the ONE next leg; -> `{jobId}` (one job at a time) |
| `POST /api/leap/toggle` `{recipient?,verify?}` | start a full round-trip; -> `{jobId}` |
| `GET /api/leap/jobs` | the current/last job summary |
| `GET /api/leap/jobs/:id` | a job's live progress: phase, legs (tx links), error, log tail |

## Roadmap

- **Phase 1 (done): read-only dashboard.** Live state + history, no actions.
- **Phase 2 (done): drive a leap.** An async job runner spawns `leap_orchestrator.mjs leg`/`toggle` as a
  background child, parses its `[INFO]/[WARN]/[ERROR]` log into phases (funding → cardano → cert → ckb → done)
  and pulls each completed leg's full record (cardano_tx, ckb_tx, cert_s) from `leap_log.jsonl`. One job at a
  time (concurrent legs would conflict on-chain). The UI's two buttons drive it (with a confirm dialog: it is a
  real testnet leap, ~6-8 min/leg) and a live step tracker (phase chips + per-leg tx links + a log tail);
  reloading mid-leap resumes the tracker.
- **Phase 3: polish.** Error surfacing, the optional Groth16 χCKB value-mint tab, a verify-mode checkbox.

Not in scope (that is the post-audit self-custody dApp): wallet-connect, user signing, the `/submit` finalize
path, real value.
