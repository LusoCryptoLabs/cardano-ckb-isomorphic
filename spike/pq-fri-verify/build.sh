#!/usr/bin/env bash
# Regenerate fixtures (host provers + adversarial batteries) and build the riscv64 CKB-VM verifiers into
# ./bin: the FRI low-degree-test verifier and the STARK verifier, each with its `bad` tampered variant.
# Run from this directory.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
T=riscv64imac-unknown-none-elf
mkdir -p "$HERE/bin"
( cd "$HERE/host"
  cargo run --release --bin prove        # writes fixtures/proof.bin + proof_bad.bin (FRI demo)
  cargo run --release --bin stark        # writes fixtures/stark.bin + stark_bad.bin (STARK)
  cargo run --release --bin ext          # writes fixtures/ext_proof.bin + _bad (F_p² secure FRI)
  cargo run --release --bin quartic      # writes fixtures/quartic_proof.bin + _bad (F_p⁴, quantum margin)
  cargo run --release --bin checkpoint   # writes fixtures/checkpoint_{proof,in,out}.bin (checkpoint-bound)
  cargo run --release --bin consensus    # writes fixtures/consensus.bin + _bad (cumulative-difficulty AIR)
  cargo run --release --bin checkpoint_consensus    # writes fixtures/consensus_cp_{proof,in,out}.bin
  cargo run --release --bin checkpoint_consensus_q ) # writes fixtures/consensus_q_{proof,in,out}.bin (composed)
( cd "$HERE/ckbvm"
  for feat in "" "--features bad"; do
    suf=""; [ -n "$feat" ] && suf="_bad"
    for b in fri_verify stark_verify ext_verify quartic_verify; do
      cargo build --release --bin "$b" $feat --target "$T"
      cp "target/$T/release/$b" "$HERE/bin/${b}${suf}.bin"
    done
  done
  for b in quartic_zc quartic_witness checkpoint consensus_verify checkpoint_consensus checkpoint_consensus_q; do
    cargo build --release --bin "$b" --target "$T"
    cp "target/$T/release/$b" "$HERE/bin/$b.bin"
  done )
echo "built: $HERE/bin/{fri_verify,stark_verify,ext_verify,quartic_verify}{,_bad}.bin + quartic_zc.bin + quartic_witness.bin"
echo "measure: ckb-debugger --bin $HERE/bin/quartic_zc.bin --mode full  # zero-copy F_p⁴ quantum-margin verify"
echo "on-chain shape (proof as tx witness):"
echo "  python3 $HERE/scripts/gen_tx.py $HERE/bin/quartic_witness.bin $HERE/fixtures/quartic_proof.bin > tx.json"
echo "  ckb-debugger --tx-file tx.json --cell-index 0 --cell-type input --script-group-type lock"
echo "production: (cd host && cargo run --release --bin quartic 22) then regenerate tx.json → fits 4 MB at n=2²²"
