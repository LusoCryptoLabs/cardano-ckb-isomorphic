# Deploying the Chiral dApp to a Linux VPS (Hostinger KVM 2)

Testnet, unaudited, low-value - but the relayer keys authorize spends, so treat `.secrets/` + `.env` as secrets.

The daemon is plain Node; the heavy pipeline (proving, Cardano/CKB txs) is python + Linux x86-64 prover ELFs
that run natively on the VPS - no WSL. The code auto-selects native bash off-Windows; `CHIRAL_NATIVE=1` pins it.

Sizing: KVM 2 (8 GB / 2 vCPU) is the target. A single forward prove transiently needs ~6 GB, and the
warm-serve prover holds the uncompressed key (~1.4 GB) plus that spike resident - so on an 8 GB box (especially
one shared with other services) run cold-per-prove (the default): the prover loads the baked `.uc`
sidecar in ~3 s, proves (~2 min on 2 vCPU), then exits and releases all memory. Always `PROVE_CONCURRENCY=1`.

> For the canonical shared-VPS pilot config (cold-per-prove, memory caps, swap, go-live checklist),
> [`deploy/PILOT_DEPLOY.md`](PILOT_DEPLOY.md) is the source of truth. This file is the generic single-box guide.

## Steps

1. Provision (as root on the VPS):
   ```sh
   git clone <your-remote> /opt/chiral # or rsync the working tree (it has uncommitted state - see note)
   cd /opt/chiral && CHIRAL_REPO_SH=/opt/chiral bash deploy/setup.sh
   ```
   `setup.sh` installs Node 20, Python 3.12 deps (pycardano 0.19.2, cbor2, blockfrost, ECPy, cryptography), aiken
   v1.1.21, runs `npm ci` for `dapp/` + `relayer/`, and builds the SPA.

   > NOTE: transfer the live state (current registry / seal / checkpoint state, restored code-cell pointers)
   > alongside the code - a fresh `git clone` alone gives the VPS stale state. the keys + prover binaries listed below

2. Transfer the non-git artifacts - prover binaries, the ~1 GB ceremony keys, the live state/configs, and the
   3 secret keys. Exact list + `rsync` lines:  the keys + prover binaries listed below.

3. Configure:
   ```sh
   mkdir -p /opt/chiral/.secrets && chmod 700 /opt/chiral/.secrets # put the 3 keys here, chmod 600 each
   cp deploy/.env.example deploy/.env # edit: CHIRAL_REPO_SH, key paths, PORT
   ```

4. Run (systemd, auto-restart):
   ```sh
   cp deploy/chiral-dapp.service /etc/systemd/system/
   systemctl daemon-reload && systemctl enable --now chiral-dapp
   curl -s localhost:8799/api/health # MUST show {"ready":true,"config":"ok","prover":"ok …"} before testers
   journalctl -u chiral-dapp -f # logs
   ```
   If health shows `prover: unreachable`, the ELF didn't run - check `file …/leap_bound_windowed` and that
   `chmod +x` was applied and glibc/libstdc++ are present.

5. (Optional - dedicated box only) Warm prover. A systemd unit holds the ceremony key resident so a prove
   skips the load. Do NOT run it resident on a small or shared 8 GB box: the arkworks prover keeps ~5 GB
   resident *after* a prove (glibc does not return it to the OS), which starves co-hosted services. The default
   cold-per-prove path already loads the baked `.uc` sidecar in ~3 s, so the warm win is marginal on this box.
   If you run it on a ≥16 GB dedicated box, bake the sidecar once with `CHIRAL_BAKE_UC=1` on the FIRST start
   (writes `<pk>.uc`, ~2× disk; later restarts load in seconds), then remove the flag. The unit sets
   `CHIRAL_SERVE` itself (kept out of `.env` so the dapp's cold-fallback prover never inherits it). On the live
   shared-VPS pilot this step is skipped - see `deploy/PILOT_DEPLOY.md`.

   > First proof is ~2 min cold on 2 vCPU - that is expected, not a hang. The dApp banner says "cold ·
   > first proof ~min" and the keys deserialize unchecked (our own ceremony output), so the load itself is fast.

6. Expose to KNOWN testers only (the prover is a DoS magnet - do NOT post a public link):
   - a reverse proxy with TLS (caddy: `caddy reverse-proxy --to localhost:8799` on your domain), or
   - `cloudflared tunnel --url http://localhost:8799` (prints a shareable https URL).

## Pre-flight before inviting anyone
- `curl /api/health` → `ready:true`.
- `curl /api/xada/config` → `ready:true`, `escrowAddress == escrowAddrHex` (forward escrow consistent).
- One real browser + wallet dry-run by you (lock → prove → mint → burn → return) - the wallet UX path hasn't
  had a real external run yet.
- Releases/returns touch shared singletons → keep them one at a time (the gates enforce this).

## Honest gaps (not blockers for a guided pilot)
- It runs on ONE box; no HA. State drift (a swept code cell, a stale pointer) needs an operator - keep an eye on
  `journalctl`. `relayer/onchain/_restore_code_cell.mjs` repairs swept code deps.
- The χADA return still re-anchors the checkpoint per return (~minutes); the warm prover removes the proof cost,
  not the re-anchor. See `spike/ckb-to-cardano/circuit/CHECKPOINT_THROUGHPUT.md`.
