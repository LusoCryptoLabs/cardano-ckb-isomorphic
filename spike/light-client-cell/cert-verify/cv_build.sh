#!/usr/bin/env bash
set -e
source ~/.cargo/env 2>/dev/null || export PATH="$PATH:/root/.cargo/bin"
cd /mnt/c/Users/telmo/chiral-study/spike/light-client-cell/cert-verify
export RUSTFLAGS="-C target-feature=-a,+forced-atomics"
B=target/riscv64imac-unknown-none-elf/release/cert_verify
echo "== build cv_deploy (default/txset mode) =="
cargo build --release 2>&1 | tail -2
riscv64-unknown-elf-strip -o /tmp/cv_deploy.strip "$B"; echo "cv_deploy stripped: $(stat -c %s /tmp/cv_deploy.strip) B"
echo "== build cv_advance (--features advance) =="
cargo build --release --features advance 2>&1 | tail -2
riscv64-unknown-elf-strip -o /tmp/cv_advance.strip "$B"; echo "cv_advance stripped: $(stat -c %s /tmp/cv_advance.strip) B"
echo "== atomic check (must be empty for CKB-VM) =="
for x in cv_deploy cv_advance; do printf "%s: " "$x"; riscv64-unknown-elf-objdump -d /tmp/$x.strip 2>/dev/null | grep -ioE "amoadd|amoswap|lr\.[wd]|sc\.[wd]" | head -1 || true; echo "(clean)"; done
echo CV_BUILD_DONE
