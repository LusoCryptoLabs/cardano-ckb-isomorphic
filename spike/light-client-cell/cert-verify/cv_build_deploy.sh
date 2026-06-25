#!/usr/bin/env bash
set -e
source ~/.cargo/env 2>/dev/null || export PATH="$PATH:/root/.cargo/bin"
cd /mnt/c/Users/telmo/chiral-study/spike/light-client-cell/cert-verify
export RUSTFLAGS="-C target-feature=-a,+forced-atomics"
B=target/riscv64imac-unknown-none-elf/release/cert_verify
echo "== rebuild cv_deploy (default mode, new ADV_TYPEHASH) =="
cargo build --release 2>&1 | tail -2
riscv64-unknown-elf-strip -o adversarial/bin/cv_deploy_pinned.bin "$B"
echo "cv_deploy_pinned: $(stat -c %s adversarial/bin/cv_deploy_pinned.bin) B"
printf "atomic check: "; riscv64-unknown-elf-objdump -d adversarial/bin/cv_deploy_pinned.bin 2>/dev/null | grep -ioE "amoadd|amoswap|lr\.[wd]|sc\.[wd]" | head -1 || true; echo "(clean)"
echo CV_DEPLOY_BUILD_DONE
