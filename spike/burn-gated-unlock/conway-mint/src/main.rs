//! Conway `mint`-field parser: extract the signed quantity of (policy_id, asset_name) from a Cardano
//! Conway transaction body. The tx body is a CBOR map; key **9** is `mint = { policy_id => { asset_name =>
//! int64 } }`. A **burn** is a negative quantity. This is the core the generalized burn-gated unlock needs:
//! instead of hardcoding the full-supply burn tx, the lock parses the *actual burned amount* and binds the
//! CKB release to it. Uses the same CBOR walker (`hdr`/`skip`) as `spike/phase1/bound_asset_unified.rs`, so
//! it ports verbatim into the no_std lock (alloc only). Host-tested below against a synthetic mint field.

/// CBOR header at `i`: returns (major, argument, next_index). Mirrors bound_asset_unified.rs.
fn hdr(b: &[u8], i: usize) -> (u8, u64, usize) {
    let ib = b[i];
    let m = ib >> 5;
    let lo = ib & 0x1f;
    match lo {
        0..=23 => (m, lo as u64, i + 1),
        24 => (m, b[i + 1] as u64, i + 2),
        25 => (m, u16::from_be_bytes([b[i + 1], b[i + 2]]) as u64, i + 3),
        26 => (m, u32::from_be_bytes([b[i + 1], b[i + 2], b[i + 3], b[i + 4]]) as u64, i + 5),
        27 => (m, u64::from_be_bytes([b[i + 1], b[i + 2], b[i + 3], b[i + 4], b[i + 5], b[i + 6], b[i + 7], b[i + 8]]), i + 9),
        _ => (m, 0, i + 1),
    }
}
/// Skip the CBOR item at `i`, returning the index just past it. Mirrors bound_asset_unified.rs.
fn skip(b: &[u8], i: usize) -> usize {
    let (m, a, mut j) = hdr(b, i);
    match m {
        0 | 1 | 7 => j,
        2 | 3 => j + a as usize,
        4 => { for _ in 0..a { j = skip(b, j); } j }
        5 => { for _ in 0..a { j = skip(b, j); j = skip(b, j); } j }
        6 => skip(b, j),
        _ => j,
    }
}

/// Signed value of a CBOR int at `i` (major 0 = +arg, major 1 = -1-arg). Returns (value, next_index).
fn cbor_int(b: &[u8], i: usize) -> (i128, usize) {
    let (m, a, j) = hdr(b, i);
    match m {
        0 => (a as i128, j),
        1 => (-1i128 - a as i128, j),
        _ => (0, skip(b, i)), // not an int (shouldn't happen in mint) - skip
    }
}

/// Parse the Conway tx body `b` and return the signed quantity minted/burned for (policy, name).
/// Burn ⇒ negative. Returns 0 if the tx has no mint field or the asset isn't present.
pub fn mint_qty(b: &[u8], policy: &[u8], name: &[u8]) -> i128 {
    let (m, n, mut i) = hdr(b, 0);
    if m != 5 { return 0; } // tx body must be a map
    for _ in 0..n {
        let (km, key, ki) = hdr(b, i); // map key (a uint)
        i = ki;
        if km == 0 && key == 9 {
            // value = mint map { policy => { name => int } }
            let (pm, pcount, mut p) = hdr(b, i);
            if pm != 5 { return 0; }
            // SEC C3: SUM every matching (policy, name) entry across ALL policy/asset blocks - do NOT
            // return on the first match. A decoy first entry can no longer mask the real net mint/burn.
            let mut acc: i128 = 0;
            for _ in 0..pcount {
                let (_bm, plen, pa) = hdr(b, p); // policy_id bytestring
                let pol = &b[pa..pa + plen as usize];
                let mut a = pa + plen as usize;
                let (am, acount, aj) = hdr(b, a); // { name => int }
                a = aj;
                if am != 5 { return 0; }
                for _ in 0..acount {
                    let (_nm, nlen, na) = hdr(b, a); // asset_name bytestring
                    let nm_bytes = &b[na..na + nlen as usize];
                    let after_name = na + nlen as usize;
                    let (qty, after_q) = cbor_int(b, after_name);
                    if pol == policy && nm_bytes == name {
                        acc += qty; // accumulate, don't early-return
                    }
                    a = after_q;
                }
                p = a;
            }
            return acc; // net minted/burned for (policy, name) across the whole mint field
        } else {
            i = skip(b, i); // skip this value
        }
    }
    0
}

// ---- host test: a synthetic Conway tx body whose mint field BURNS the bridged asset ----
fn build_synthetic(policy: &[u8; 28], name: &[u8], burn_qty: u64) -> Vec<u8> {
    // map(2): { 0: [dummy input set], 9: { policy: { name: -burn_qty } } }
    let mut b = Vec::new();
    b.push(0xA2); // map(2)
    // key 0 (inputs) -> empty array (dummy, just to exercise skip)
    b.push(0x00);
    b.push(0x80); // array(0)
    // key 9 (mint)
    b.push(0x09);
    b.push(0xA1); // map(1): one policy
    b.push(0x58); b.push(28); b.extend_from_slice(policy); // bytes(28) policy_id
    b.push(0xA1); // map(1): one asset
    b.push(0x40 + name.len() as u8); b.extend_from_slice(name); // bytes(name) (len<24)
    // negative quantity = -burn_qty  => CBOR major 1, arg = burn_qty-1
    let arg = burn_qty - 1;
    if arg < 24 { b.push(0x20 + arg as u8); }
    else if arg < 256 { b.push(0x38); b.push(arg as u8); }
    else if arg < 65536 { b.push(0x39); b.extend_from_slice(&(arg as u16).to_be_bytes()); }
    else { b.push(0x3a); b.extend_from_slice(&(arg as u32).to_be_bytes()); }
    b
}

fn main() {
    let policy = [0xabu8; 28];
    let name = b"ckCKB";
    for &q in &[1u64, 23, 100, 100_000, 65000] {
        let tx = build_synthetic(&policy, name, q);
        let got = mint_qty(&tx, &policy, name);
        let want = -(q as i128);
        let other = mint_qty(&tx, &[0u8; 28], name); // wrong policy -> 0
        println!("burn {:>7}: parsed {:>9} (want {:>9})  ok={}  wrong_policy={}", q, got, want, got == want, other == 0);
        assert_eq!(got, want, "mint_qty extracted the wrong burn amount");
        assert_eq!(other, 0, "wrong policy must not match");
    }
    println!("conway mint-field burn-amount parser: OK (ports into the no_std lock; reads tx body from witness)");
}
