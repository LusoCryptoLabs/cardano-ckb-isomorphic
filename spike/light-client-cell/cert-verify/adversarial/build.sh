#!/usr/bin/env bash
# Rebuild the three cert-verify verifier modes used by the adversarial suite and
# stage them (stripped) into ./bin. Run from this directory. Requires the RISC-V
# Rust target + riscv64-unknown-elf-strip (same toolchain as the rest of the repo).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CRATE="$HERE/.."
T=riscv64imac-unknown-none-elf
STRIP=${STRIP:-riscv64-unknown-elf-strip}
OUT="$CRATE/target/$T/release/cert_verify"
mkdir -p "$HERE/bin"
cd "$CRATE"
build () { local feat="$1" name="$2"; cargo build --release $feat --target "$T"; "$STRIP" -o "$HERE/bin/$name" "$OUT"; }
build "--features standalone" cv_standalone.bin
build ""                      cv_deploy.bin
build "--features advance"    cv_advance.bin
echo "staged: $HERE/bin/{cv_standalone,cv_deploy,cv_advance}.bin"
# Note: cv_advance.bin must hash to codeHash 0xe877a8028eac379e962a596671d1cd918aceddfa4c4cd78163168ba3b533ac55
# (type-hash 0x59efd99d...), which the deploy-mode ADV_TYPEHASH constant binds to. If your strip/toolchain
# yields a different size, the codeHash will differ from the deployed canonical advance verifier.
