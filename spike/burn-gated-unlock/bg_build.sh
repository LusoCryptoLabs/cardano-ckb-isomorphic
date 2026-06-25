#!/usr/bin/env bash
# BG2: build the deployable burn_gated_unlock_v2 (atomic-free + stripped, or the on-chain CKB-VM rejects it).
set -e
source ~/.cargo/env 2>/dev/null || true
cd /mnt/c/Users/telmo/chiral-study/spike/burn-gated-unlock
RUSTFLAGS="-C target-feature=-a,+forced-atomics" cargo build --release --bin burn_gated_unlock_v2 \
  --target riscv64imac-unknown-none-elf 2>&1 | tail -4
B=target/riscv64imac-unknown-none-elf/release/burn_gated_unlock_v2
riscv64-unknown-elf-strip -o "$B.strip" "$B"
echo "stripped size: $(stat -c %s "$B.strip") bytes"
echo "raw-atomic check (must be empty for the no-A-extension CKB-VM):"
riscv64-unknown-elf-objdump -d "$B.strip" 2>/dev/null | grep -ioE "amoadd|amoswap|lr\.[wd]|sc\.[wd]" | head || true
echo "BG_BUILD_DONE"
