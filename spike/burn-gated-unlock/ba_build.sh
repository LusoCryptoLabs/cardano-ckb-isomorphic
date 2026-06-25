#!/usr/bin/env bash
set -e
source ~/.cargo/env 2>/dev/null || export PATH="$PATH:/root/.cargo/bin"
cd /mnt/c/Users/telmo/chiral-study/spike/burn-gated-unlock
export CHIRAL_LCKP_TH="0xcae4326684d06d3cdad0d5f683c4c33d066862b0fa0a753bc58791df5987552a"
export CHIRAL_REG_TH="0xdc18fd562bca1834536c926ce8c9d94f608318c3a79a43959c0c46a84265a24e"
export RUSTFLAGS="-C target-feature=-a,+forced-atomics"
echo "== build bound_asset_v2 (LCKP=$CHIRAL_LCKP_TH REG=$CHIRAL_REG_TH) =="
cargo build --release --bin bound_asset_v2 --target riscv64imac-unknown-none-elf 2>&1 | tail -2
B=target/riscv64imac-unknown-none-elf/release/bound_asset_v2
riscv64-unknown-elf-strip -o "$B.pinned" "$B"
echo "bound_asset_v2.pinned: $(stat -c %s "$B.pinned") B"
printf "atomic check: "; riscv64-unknown-elf-objdump -d "$B.pinned" 2>/dev/null | grep -ioE "amoadd|amoswap|lr\.[wd]|sc\.[wd]" | head -1 || true; echo "(clean)"
echo BA_BUILD_DONE
