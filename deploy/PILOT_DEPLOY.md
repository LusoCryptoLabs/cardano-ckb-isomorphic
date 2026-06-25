# Chiral pilot - VPS go-live checklist

Guided testnet pilot on a Hostinger KVM2 (8 GB / 2 vCPU). Unaudited, no real value. Expose to KNOWN
testers only - never a public link (the prover is a DoS magnet; the χADA escrow return-vk is a drainable
placeholder capped at 5 ADA). Live forward χCKB policy: `5b4f5525a155fd86757bb3ba20da6e2ef66bcfb72e8853ef31bcf268`.

## 1. Code
```sh
git clone -b perf/pilot-optimizations https://github.com/LusoCryptoLabs/cardano-ckb-isomorphic.git /opt/chiral
```

## 2. Keys - OUT-OF-BAND, never via git (all gitignored)
Copy to `/opt/chiral/.secrets/` and `chmod 600`:
- `relay_bind_pk.bin` (~706 MB forward ceremony key) → `spike/ckb-to-cardano/circuit/ceremony_relay_bind/`.
  This is the key whose vk == the deployed policy `5b4f5525…`. It must travel with the matching policy -
  re-keying produces a new policy id, so don't regenerate it independently.
- `leap_bound_windowed_pk.bin` (~751 MB return ceremony key) → `spike/ckb-to-cardano/circuit/ceremony_xada_burn/`.
- `pudge_relayer.key` (CKB relayer), `preview_relayer.key` (Cardano relayer + governor).

## 3. `deploy/.env` (copy from `.env.example`, then set)
```ini
CHIRAL_NATIVE=1
CHIRAL_REPO_SH=/opt/chiral
PORT=8799
PROVE_CONCURRENCY=1
CHI_POLICY_ID=5b4f5525a155fd86757bb3ba20da6e2ef66bcfb72e8853ef31bcf268
CHIRAL_ACCESS_TOKEN=<a long random secret> # gate the heavy endpoints
CHIRAL_STABLE_REGISTRY=1 # E2 registry (no per-return re-genesis)
RELAYER_KEY=/opt/chiral/.secrets/pudge_relayer.key
CHIRAL_PREVIEW_KEY=/opt/chiral/.secrets/preview_relayer.key
RELAY_WARM_SOCK=/tmp/chiral_relay_warm.sock
# CEREMONY_PK + CHIRAL_SERVE live ONLY in the warm-prover unit, NOT here.
```

## 4. Build the frontend
```sh
cd /opt/chiral/dapp && npm ci && npm run build
```

## 5. Services (systemd)
- `deploy/chiral-warmprover-forward.service` - point `CEREMONY_PK` at the forward key; first start with
  `CHIRAL_BAKE_UC=1` to write the `.uc` sidecar (then remove it; later starts load in seconds).
- `deploy/chiral-dapp.service`.
- 8 GB tuning: the forward warm prover holds ~1.4 GB resident and a single prove transiently spikes well
  above that - raise `MemoryMax` (≥6 G) on the forward unit and provision swap so a prove can't be OOM-killed.
  Don't run both warm provers at full size on 8 GB; the χCKB return is keyless/Mithril-gated and less
  latency-sensitive, so run the FORWARD one resident and let returns cold-fallback (or scale the box).
```sh
sudo cp deploy/chiral-*.service /etc/systemd/system/ && sudo systemctl daemon-reload
sudo systemctl enable --now chiral-warmprover-forward chiral-dapp
```

## 6. TLS front + access
- `deploy/nginx-chiral.conf.example` → nginx, `certbot` for TLS.
- Hand each tester the link `https://host/?t=<CHIRAL_ACCESS_TOKEN>` (the dApp strips `?t=` into storage and
  sends it on heavy calls). Rotate the token to revoke a cohort.

## 7. Verify before inviting testers
```sh
curl -s https://host/api/health # ready:true, warm:true
curl -s https://host/api/bridge/config # burnGated.policyId == 5b4f5525…
```
Then run one real forward leap end-to-end (lock → prove → mint χCKB on Cardano) and one χADA round trip.

## 8. Tester guidance
- Fund the CKB lock from a SINGLE cell ≥ ~365 CKB (a fresh faucet cell qualifies). The forward proof is
  keyed to a canonical 1-input lock layout; a fragmented wallet gets a clear "consolidate" error.
- Guided cohort: ~5–20 connected, the heavy pipeline serializes (~1–2 active leaps at a time); the queue UI
  shows position. χADA forward + χCKB return are Mithril-gated (~7–10 min) - that's a latency floor, not a bug.
