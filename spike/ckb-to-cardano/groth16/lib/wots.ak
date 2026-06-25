//// Post-quantum Cardano-side verifier - feasibility by construction. A hash-based FRI/STARK verifier does
//// NOT fit a Plutus tx (PLUTUS_PQ_COST.md). But a hash-based *signature* does: its verification is only
//// ~1000 blake2b hashes (well under the ~4,800-hash per-tx memory cap). This is a real Winternitz one-time
//// signature (WOTS+, the core of XMSS / SPHINCS+ - all hash-only ⇒ post-quantum) verified in Aiken, so the
//// Cardano leg can authenticate the counterparty chain with a PQ certificate instead of Mithril's BLS.
//// `aiken check` reports the ExUnits; verify cost = (full round-trip) − (keygen+sign).
use aiken/builtin
use aiken/crypto.{blake2b_256}
use aiken/collection/list

const w: Int = 16          // Winternitz parameter (4 bits / digit)
const total_len: Int = 67  // len1 = 64 (256-bit message, 4-bit digits) + len2 = 3 (checksum)

/// One hash-chain: apply blake2b_256 `n` times.
fn chain(b: ByteArray, n: Int) -> ByteArray {
  if n <= 0 {
    b
  } else {
    chain(blake2b_256(b), n - 1)
  }
}

/// The 64 base-16 digits of a 32-byte message digest (high nibble then low, per byte).
fn nibbles(msg: ByteArray) -> List<Int> {
  list.foldr(
    list.range(0, 31),
    [],
    fn(i, acc) {
      let byte = builtin.index_bytearray(msg, i)
      [byte / 16, byte % 16, ..acc]
    },
  )
}

/// WOTS+ checksum (3 base-16 digits of Σ (w-1 − d_i)).
fn checksum(ds: List<Int>) -> List<Int> {
  let s = list.foldl(ds, 0, fn(d, a) { a + (w - 1 - d) })
  [s / 256 % 16, s / 16 % 16, s % 16]
}

fn digits(msg: ByteArray) -> List<Int> {
  let d = nibbles(msg)
  list.concat(d, checksum(d))
}

/// secret-key element i (placeholder seed; values are irrelevant to the *cost* we measure).
fn sk(i: Int) -> ByteArray {
  blake2b_256(builtin.cons_bytearray(i, "wots-seed-"))
}

/// public key: pk_i = H^{w-1}(sk_i)
fn keygen() -> List<ByteArray> {
  list.map(list.range(0, total_len - 1), fn(i) { chain(sk(i), w - 1) })
}

/// signature: sig_i = H^{d_i}(sk_i)
fn sign(ds: List<Int>) -> List<ByteArray> {
  list.indexed_map(ds, fn(i, d) { chain(sk(i), d) })
}

/// verify: H^{w-1−d_i}(sig_i) == pk_i for every chain.
fn wots_verify(ds: List<Int>, sig: List<ByteArray>, pk: List<ByteArray>) -> Bool {
  let recomputed =
    list.indexed_map(
      sig,
      fn(i, s) {
        expect Some(d) = list.at(ds, i)
        chain(s, w - 1 - d)
      },
    )
  recomputed == pk
}

test wots_keysign() {
  // baseline: keygen + sign only (no verify)
  let ds = digits(blake2b_256("ckb checkpoint @ epoch 8"))
  let pk = keygen()
  let sig = sign(ds)
  list.length(pk) == total_len && list.length(sig) == total_len
}

test wots_full() {
  // keygen + sign + VERIFY (a full hash-based-signature round-trip)
  let ds = digits(blake2b_256("ckb checkpoint @ epoch 8"))
  let pk = keygen()
  let sig = sign(ds)
  wots_verify(ds, sig, pk)
}
