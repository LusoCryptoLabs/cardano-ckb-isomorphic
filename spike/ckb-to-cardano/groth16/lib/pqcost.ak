//// Plutus cost keystone for a POST-QUANTUM (hash-based FRI/STARK) verifier on the Cardano side. Unlike
//// CKB-VM, Plutus has no general-purpose VM - every hash and field op is an interpreted Plutus-Core builtin,
//// and there is NO native FRI/Merkle/Goldilocks acceleration (only BLS12-381, which is why Groth16 fits).
//// These tests micro-benchmark the two primitives a hash-based verifier is made of; `aiken check` reports the
//// ExUnits (mem, cpu-steps) per test, so per-op cost = (cost at 2N − cost at N) / N. Combined with the op
//// counts measured for the CKB-VM verifier, this estimates whether such a verifier fits Cardano's per-tx
//// budget (mem 14,000,000 ; cpu-steps 10,000,000,000 on Plutus v3 mainnet).
use aiken/crypto.{blake2b_256}
use aiken/primitive/bytearray

const p: Int = 18446744069414584321
// Goldilocks (2^64 − 2^32 + 1)

fn hash_chain(n: Int, acc: ByteArray) -> ByteArray {
  if n == 0 {
    acc
  } else {
    // a 2-to-1 Merkle node hash: blake2b_256 over the 64-byte concatenation of two 32-byte children
    hash_chain(n - 1, blake2b_256(bytearray.concat(acc, acc)))
  }
}

fn fmul_chain(n: Int, acc: Int, x: Int) -> Int {
  if n == 0 {
    acc
  } else {
    // Goldilocks field multiplication: arbitrary-precision multiply + reduce
    fmul_chain(n - 1, acc * x % p, x)
  }
}

test bench_hash_1000() {
  bytearray.length(hash_chain(1000, #"0001020304050607080910111213141516171819202122232425262728293031")) == 32
}

test bench_hash_2000() {
  bytearray.length(hash_chain(2000, #"0001020304050607080910111213141516171819202122232425262728293031")) == 32
}

test bench_fmul_1000() {
  fmul_chain(1000, 123456789, 0x9e3779b97f4a7c15) >= 0
}

test bench_fmul_2000() {
  fmul_chain(2000, 123456789, 0x9e3779b97f4a7c15) >= 0
}
