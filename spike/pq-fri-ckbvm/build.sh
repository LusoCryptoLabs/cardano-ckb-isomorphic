#!/usr/bin/env bash
# Build the three single-primitive bench workloads into ./bin and print how to measure them.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
T=riscv64imac-unknown-none-elf
mkdir -p "$HERE/bin"
cd "$HERE"
for feat in baseline hash fmul; do
  cargo build --release --features "$feat" --target "$T"
  cp "target/$T/release/bench" "$HERE/bin/bench_$feat.bin"
done
echo "built: $HERE/bin/bench_{baseline,hash,fmul}.bin"
echo "measure: ckb-debugger --bin $HERE/bin/bench_<feat>.bin --mode full   # read 'All cycles'"
