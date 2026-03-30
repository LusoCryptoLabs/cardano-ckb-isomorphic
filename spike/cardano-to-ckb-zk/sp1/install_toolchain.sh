#!/usr/bin/env bash
# Install the SP1 'succinct' Rust toolchain MANUALLY.
# Why: in sandboxes behind an egress proxy with a custom CA, `cargo prove install-toolchain` fails with
# "error sending request" (its bundled-reqwest TLS doesn't trust the proxy CA), while curl/cargo (system
# CA) work. cargo-prove also needs an authenticated GitHub API call (unauth 60/hr is too low). So we
# download the toolchain asset with curl + $GITHUB_TOKEN and link it ourselves.
# Requires: sp1up + cargo-prove already installed (curl -L https://sp1.succinct.xyz | bash), $GITHUB_TOKEN set.
set -euo pipefail
: "${GITHUB_TOKEN:?set GITHUB_TOKEN (a scopeless PAT is enough)}"
TC="succinct-1.94.0-64bit"   # the version cargo-prove (sp1 v6.2.3) pins; check `strings ~/.sp1/bin/cargo-prove`
ASSET="rust-toolchain-x86_64-unknown-linux-gnu.tar.gz"
api="https://api.github.com/repos/succinctlabs/rust/releases"
url=$(curl -s -H "Authorization: Bearer $GITHUB_TOKEN" "$api?per_page=20" \
  | python3 -c "import sys,json;d=json.load(sys.stdin);r=[x for x in d if x['tag_name']=='$TC'][0];print([a['url'] for a in r['assets'] if a['name']=='$ASSET'][0])")
echo "downloading $TC ..."
curl -sL -H "Authorization: Bearer $GITHUB_TOKEN" -H "Accept: application/octet-stream" "$url" -o /tmp/sp1_tc.tar.gz
mkdir -p ~/.sp1/toolchains/succinct
tar -xzf /tmp/sp1_tc.tar.gz -C ~/.sp1/toolchains/succinct --exclude 'lib/rustlib/src' --exclude 'lib/rustlib/rustc-src'
rustup toolchain link succinct ~/.sp1/toolchains/succinct
# the asset ships rustc but not cargo; SP1 uses the host cargo with its rustc
ln -sf "$(rustup which cargo)" ~/.sp1/toolchains/succinct/bin/cargo
echo "installed: $(~/.sp1/toolchains/succinct/bin/rustc --version)"
~/.sp1/toolchains/succinct/bin/rustc --print target-list | grep -q riscv32im-succinct-zkvm-elf && echo "SP1 zkVM target OK"
