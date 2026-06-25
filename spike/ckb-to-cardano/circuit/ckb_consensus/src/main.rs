// Validate CKB's consensus primitives on a REAL Pudge block (21,340,780) - the exact relations the
// zk-circuit must encode. Proves: (1) the RawHeader molecule serialization + ckbhash reproduce the
// block hash; (2) EaglesongBlake2b(pow_hash ‖ nonce) ≤ target_from_compact - i.e. the real header's
// proof-of-work, recomputed from scratch. Uses CKB's own reference crates (eaglesong + blake2b),
// which ARE the spec the circuit must match.
use blake2b_rs::Blake2bBuilder;
use eaglesong::eaglesong;

fn ckbhash(data: &[u8]) -> [u8; 32] {
    let mut h = Blake2bBuilder::new(32).personal(b"ckb-default-hash").build();
    h.update(data); let mut o = [0u8; 32]; h.finalize(&mut o); o
}
fn hx(s: &str) -> Vec<u8> { let s = s.trim_start_matches("0x"); (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i+2],16).unwrap()).collect() }
fn rev32(b: &[u8;32]) -> [u8;32] { let mut o=[0u8;32]; for i in 0..32 { o[i]=b[31-i]; } o }

// Bitcoin-style compact target -> 32-byte big-endian target.
fn target_from_compact(compact: u32) -> [u8;32] {
    let exp = (compact >> 24) as usize;
    let mant = compact & 0x007f_ffff;
    let mut t = [0u8;32];
    let m = mant.to_be_bytes(); // 4 bytes, mant in low 3
    // place the 3 mantissa bytes so the value = mant * 256^(exp-3)
    for k in 0..3 {
        let pos = 32 - exp + k;
        if pos < 32 { t[pos] = m[1+k]; }
    }
    t
}

fn main() {
    // RawHeader fields (block 21,340,780, testnet.ckb.dev)
    let version: u32 = 0x0;
    let compact_target: u32 = 0x1d083f14;
    let timestamp: u64 = 0x19e9f27a98e;
    let number: u64 = 0x145a26c;
    let epoch: u64 = 0x70801bb0033ab;
    let parent_hash = hx("ff9f61a483a8aa3e3e07ab042def617b539c7f3a6c8798fabc9ae014fc4eb124");
    let transactions_root = hx("5223aafc3ff498c720c82e2e27efc43fa5e3b34f6d30d159383240af4d5c2dc0");
    let proposals_hash = hx("0000000000000000000000000000000000000000000000000000000000000000");
    let extra_hash = hx("d309cfe05d10d894aa09750744d6028a69798b09a07b53ba78c8e8ebbdb392f6");
    let dao = hx("56399b9741782757b33e00eb3a132a0042aa26d04abae10900dd46fae8d35709");
    let nonce: u128 = 0x3776a47439d967800e52a31e76fa8d8a;
    let expected_hash = hx("3dc9a017f6a8c84ab3c59318339021d9975a1ac67b7e52e5765240c5b93cc53a");

    // RawHeader molecule = fixed struct = concat of LE-encoded fields (192 bytes)
    let mut raw = Vec::new();
    raw.extend_from_slice(&version.to_le_bytes());
    raw.extend_from_slice(&compact_target.to_le_bytes());
    raw.extend_from_slice(&timestamp.to_le_bytes());
    raw.extend_from_slice(&number.to_le_bytes());
    raw.extend_from_slice(&epoch.to_le_bytes());
    raw.extend_from_slice(&parent_hash);
    raw.extend_from_slice(&transactions_root);
    raw.extend_from_slice(&proposals_hash);
    raw.extend_from_slice(&extra_hash);
    raw.extend_from_slice(&dao);
    assert_eq!(raw.len(), 192, "RawHeader must be 192 bytes");

    // (1) block hash = ckbhash(RawHeader ‖ nonce_le16)
    let mut header = raw.clone();
    header.extend_from_slice(&nonce.to_le_bytes());
    let block_hash = ckbhash(&header);
    println!("(1) block hash recomputed = {}", hex(&block_hash));
    println!("    expected             = {}", hex(&expected_hash));
    let hash_ok = block_hash.as_slice() == expected_hash.as_slice();
    println!("    HEADER HASH MATCHES  = {hash_ok}");

    // (2) PoW: pow_hash = ckbhash(RawHeader);  input = pow_hash ‖ nonce_le16;
    //     EaglesongBlake2b output = ckbhash(eaglesong(input));  compare ≤ target (output is LE U256)
    let pow_hash = ckbhash(&raw);                         // ckbhash(RawHeader)
    let mut input = pow_hash.to_vec();
    input.extend_from_slice(&nonce.to_le_bytes());        // pow_message = pow_hash ‖ nonce_le16 (48 B)
    let mut eag = [0u8; 32];
    eaglesong(&input, &mut eag);                          // EaglesongBlake2b:
    let pow_output = ckbhash(&eag);                       //   ckbhash(eaglesong(pow_message))
    let target = target_from_compact(compact_target);
    println!("(2) pow_output (BE)     = {}", hex(&pow_output));
    println!("    target              = {}", hex(&target));
    let pow_ok = le_leq(&pow_output, &target);            // interpreted BIG-ENDIAN as U256
    println!("    POW VALID (≤ target)= {pow_ok}");

    if hash_ok && pow_ok {
        println!("\nVALIDATED: the real CKB header's hash + Eaglesong PoW recompute from scratch. These are the exact relations the circuit must prove.");
    } else { println!("\nMISMATCH - check serialization / pow construction"); std::process::exit(1); }
}

fn le_leq(a: &[u8;32], b: &[u8;32]) -> bool { // big-endian arrays: a <= b ?
    for i in 0..32 { if a[i] != b[i] { return a[i] < b[i]; } } true
}
fn hex(b: &[u8]) -> String { b.iter().map(|x| format!("{:02x}", x)).collect() }
