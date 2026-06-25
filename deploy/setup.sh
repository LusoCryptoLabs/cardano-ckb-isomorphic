#!/usr/bin/env bash
# setup.sh - provision a fresh Ubuntu/Debian VPS (Hostinger KVM 2, 8GB) to run the Chiral dApp daemon natively.
# Idempotent-ish; re-runnable. Run as root (or with sudo). Pins the toolchain captured from the dev box
# (ChiralSP1): Python 3.12, pycardano 0.19.2 + cbor2/blockfrost/ECPy/cryptography, aiken v1.1.21, Node 20+.
set -euo pipefail
REPO="${CHIRAL_REPO_SH:-/opt/chiral}"

echo "==> apt deps"
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y curl ca-certificates git build-essential pkg-config libssl-dev \
  python3 python3-pip python3-venv jq file

echo "==> swap (the warm prover loads the ~480MB key into a multi-GB resident set; give the 8GB box headroom so"
echo "    a transient spike degrades to slow instead of an OOM-kill - the SPA build also benefits)"
if [ "$(swapon --show --noheadings | wc -l)" -eq 0 ] && [ ! -f /swapfile ]; then
  fallocate -l 4G /swapfile 2>/dev/null || dd if=/dev/zero of=/swapfile bs=1M count=4096
  chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile
  grep -q '/swapfile' /etc/fstab 2>/dev/null || echo '/swapfile none swap sw 0 0' >> /etc/fstab
  echo "    created /swapfile (4G)"
else
  echo "    swap already present - skipping"
fi

echo "==> Node 20 LTS (server.mjs + the ccc orchestrators)"
if ! command -v node >/dev/null || [ "$(node -v | cut -dv -f2 | cut -d. -f1)" -lt 20 ]; then
  curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
  apt-get install -y nodejs
fi
node -v

echo "==> Python deps (match ChiralSP1; --break-system-packages on PEP668 distros, or use a venv)"
python3 -m pip install --break-system-packages \
  "pycardano==0.19.2" "cbor2==5.6.5" "blockfrost-python==0.7.0" "ECPy==1.2.5" "cryptography==48.0.0" "requests==2.34.2" \
  || python3 -m pip install "pycardano==0.19.2" "cbor2==5.6.5" "blockfrost-python==0.7.0" "ECPy==1.2.5" "requests==2.34.2"

echo "==> aiken v1.1.21 (validators are rebuilt at release time)"
if ! command -v aiken >/dev/null && [ ! -x "$HOME/.aiken/bin/aiken" ]; then
  curl -fsSL https://install.aiken-lang.org | bash || true
  if command -v aikup >/dev/null; then aikup install v1.1.21 || aikup; fi
fi
("$HOME/.aiken/bin/aiken" --version 2>/dev/null || aiken --version 2>/dev/null || echo "WARN: install aiken v1.1.21 manually")

echo "==> repo layout"
mkdir -p "$REPO/.secrets"
chmod 700 "$REPO/.secrets"
echo "    (put the repo at $REPO, the keys in $REPO/.secrets, and deploy/.env there too)"

echo "==> node deps (rebuild on this host - do NOT copy node_modules from the dev box)"
# relayer runs the orchestrators at runtime -> install runtime deps only (no devDeps in its package.json anyway).
if [ -d "$REPO/relayer" ];  then (cd "$REPO/relayer" && npm ci --omit=dev || npm install --omit=dev); fi
# dapp needs its devDeps (vite + plugins) to BUILD the SPA; the daemon (server.mjs) imports ZERO npm
# packages (Node built-ins + ../relayer/onchain/_rt.mjs only), so dapp/node_modules is build-only.
if [ -d "$REPO/dapp" ];     then (cd "$REPO/dapp" && npm ci || npm install); fi

echo "==> mark the prover ELFs executable"
chmod +x "$REPO"/spike/ckb-to-cardano/circuit/prover/target/release/* 2>/dev/null || true

echo "==> build the SPA"
if [ -d "$REPO/dapp" ]; then (cd "$REPO/dapp" && npm run build); fi

# Optional space reclaim: dapp/node_modules is build-only (the daemon serves dist/ with Node built-ins).
# Set CHIRAL_PRUNE_BUILD_DEPS=1 to drop it after a successful build (re-run this script to rebuild later).
if [ "${CHIRAL_PRUNE_BUILD_DEPS:-0}" = "1" ] && [ -d "$REPO/dapp/dist" ]; then
  echo "==> pruning build-only dapp/node_modules (CHIRAL_PRUNE_BUILD_DEPS=1)"
  rm -rf "$REPO/dapp/node_modules"
fi

cat <<EOF

==> NEXT (manual):
  1) Put the 3 key files in $REPO/.secrets (chmod 600) and copy deploy/.env.example -> $REPO/deploy/.env (edit paths).
  2) Verify the prover runs:  $REPO/spike/ckb-to-cardano/circuit/prover/target/release/leap_bound_windowed --help 2>/dev/null; echo "(exit ok = ELF runs)"
  3) Install the service:     cp $REPO/deploy/chiral-dapp.service /etc/systemd/system/ && systemctl daemon-reload && systemctl enable --now chiral-dapp
  4) Warm prover (~8s returns vs ~6.7min): cp $REPO/deploy/chiral-warmprover.service /etc/systemd/system/ && systemctl enable --now chiral-warmprover
     First start loads the key (~6.5min, or seconds if you baked the .uc sidecar - set CHIRAL_BAKE_UC=1 once).
  5) Health:                  curl -s localhost:${PORT:-8799}/api/health   # "ready":true, and "warm":true once (4) is up
  6) Expose to known testers (TLS): a reverse proxy (caddy/nginx) or  cloudflared tunnel --url http://localhost:${PORT:-8799}
EOF
