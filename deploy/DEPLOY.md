# Deploying the Chiral dApp to a Linux VPS (Hostinger KVM 2)

Testnet, unaudited, low-value — but the relayer keys authorize spends, so treat `.secrets/` + `.env` as secrets.

The daemon is plain Node; the heavy pipeline (proving, Cardano/CKB txs) is python + **Linux x86-64 prover ELFs**
that run **natively** on the VPS — no WSL. The code auto-selects native bash off-Windows; `CHIRAL_NATIVE=1` pins it.

**Sizing:** KVM 2 (8 GB / 2 vCPU) is the target. The warm prover holds the 480 MB key resident (multi-GB); run one
prover at a time (`PROVE_CONCURRENCY=1`). The 4 GB plan only works with swap and is slow — avoid for the prover.

## Steps

1. **Provision** (as root on the VPS):
   ```sh
   git clone <your-remote> /opt/chiral          # or rsync the working tree (it has uncommitted state — see note)
   cd /opt/chiral && CHIRAL_REPO_SH=/opt/chiral bash deploy/setup.sh
   ```
   `setup.sh` installs Node 20, Python 3.12 deps (pycardano 0.19.2, cbor2, blockfrost, ECPy, cryptography), aiken
   v1.1.21, runs `npm ci` for `dapp/` + `relayer/`, and builds the SPA.

   > NOTE: this session left **uncommitted changes + live state** on the dev box (portability layer, the warm
   > prover, restored code-cell pointers, current registry/seal/checkpoint state). Either commit & push first, or
   > `rsync` the working tree — otherwise the VPS gets stale state. See `deploy/MANIFEST.md`.

2. **Transfer the non-git artifacts** — prover binaries, the ~1 GB ceremony keys, the live state/configs, and the
   3 secret keys. Exact list + `rsync` lines: **`deploy/MANIFEST.md`**.

3. **Configure**:
   ```sh
   mkdir -p /opt/chiral/.secrets && chmod 700 /opt/chiral/.secrets   # put the 3 keys here, chmod 600 each
   cp deploy/.env.example deploy/.env                                 # edit: CHIRAL_REPO_SH, key paths, PORT
   ```

4. **Run** (systemd, auto-restart):
   ```sh
   cp deploy/chiral-dapp.service /etc/systemd/system/
   systemctl daemon-reload && systemctl enable --now chiral-dapp
   curl -s localhost:8799/api/health         # MUST show {"ready":true,"config":"ok","prover":"ok …"} before testers
   journalctl -u chiral-dapp -f              # logs
   ```
   If health shows `prover: unreachable`, the ELF didn't run — check `file …/leap_bound_windowed` and that
   `chmod +x` was applied and glibc/libstdc++ are present.

5. **Warm prover (~8 s returns vs ~6.7 min)** — a systemd unit (`deploy/chiral-warmprover.service`) holds the
   ceremony key resident. `CEREMONY_PK`/`WINDOW_DEPTH`/`CHIRAL_K_MIN`/`CHIRAL_WARM_SOCK` come from `deploy/.env`;
   the unit sets `CHIRAL_SERVE` itself (kept out of `.env` so the dapp's cold-fallback prover never inherits it):
   ```sh
   cp deploy/chiral-warmprover.service /etc/systemd/system/
   systemctl daemon-reload && systemctl enable --now chiral-warmprover
   journalctl -u chiral-warmprover -f      # watch for "pk loaded in …s; serving on …"
   ```
   It loads the key once, then `xada_burn_orchestrate` proves warm-first (cold fallback). `/api/health` shows
   `"warm":true` once it's up. **First-load speedup:** set `CHIRAL_BAKE_UC=1` in `.env` for the FIRST start to
   write an uncompressed key sidecar (`<pk>.uc`, ~2× disk); every later restart then loads in seconds, not minutes.
   Remove `CHIRAL_BAKE_UC` once the sidecar exists. (The default compressed load is already much faster than
   before — keys now deserialize unchecked since they're our own ceremony output.)

6. **Expose to KNOWN testers only** (the prover is a DoS magnet — do NOT post a public link):
   - a reverse proxy with TLS (caddy: `caddy reverse-proxy --to localhost:8799` on your domain), or
   - `cloudflared tunnel --url http://localhost:8799` (prints a shareable https URL).

## Pre-flight before inviting anyone
- `curl /api/health` → `ready:true`.
- `curl /api/xada/config` → `ready:true`, `escrowAddress == escrowAddrHex` (forward escrow consistent).
- One real **browser + wallet** dry-run by you (lock → prove → mint → burn → return) — the wallet UX path hasn't
  had a real external run yet.
- Releases/returns touch shared singletons → keep them **one at a time** (the gates enforce this).

## Honest gaps (not blockers for a guided pilot)
- It runs on ONE box; no HA. State drift (a swept code cell, a stale pointer) needs an operator — keep an eye on
  `journalctl`. `relayer/onchain/_restore_code_cell.mjs` repairs swept code deps.
- The χADA return still re-anchors the checkpoint per return (~minutes); the warm prover removes the proof cost,
  not the re-anchor. See `spike/ckb-to-cardano/circuit/CHECKPOINT_THROUGHPUT.md`.
