//! bound_asset.rs - §6.2 + §6.3: in-script Conway tx-body parsing + the BoundAsset transition.
//! Parses a real Cardano (Conway) tx body's CBOR to (a) extract the input set [seal detection] and
//! (b) extract output[0]'s inline-datum [the commitment]. The BoundAsset transition (the actual
//! isomorphic-binding step) then requires: the seal OP is consumed AND commitment ==
//! blake2b256(new_state || new_seal). Consumes the cross-chain oracle (cardano_tx_is_certified)
//! as a black box (proven separately in spike/cross-chain). lock[0]=mode: 0=§6.2 real-tx parse,
//! 1=§6.3 full transition on a constructed seal-spend.
#![cfg_attr(not(test), no_std)]
#![cfg_attr(not(test), no_main)]
use alloc::vec::Vec;
use ckb_std::{ckb_constants::Source, high_level::load_witness_args};
#[cfg(not(test))] ckb_std::entry!(program_entry);
#[cfg(not(test))] ckb_std::default_alloc!();

// real preview tx (64fbcc23…) body + its real seal input (3c2dce14…#1)
const REAL_BODY: &[u8] = &[163,0,217,1,2,129,130,88,32,60,45,206,20,202,195,143,176,54,21,32,74,108,107,131,103,7,58,176,41,192,217,170,112,102,81,201,188,212,178,210,48,1,1,130,163,0,88,29,112,21,162,221,176,210,109,17,245,24,89,201,116,132,245,202,130,30,127,231,111,151,30,223,254,141,81,10,6,1,130,26,0,30,132,128,161,88,28,216,144,108,165,199,186,18,74,4,7,163,45,171,55,178,200,43,19,179,220,217,17,30,66,148,13,206,164,161,69,85,83,68,67,120,26,29,205,101,0,2,130,1,216,24,88,180,216,121,159,216,121,159,88,28,238,131,95,142,53,109,119,79,84,185,5,152,204,83,244,76,191,137,75,87,202,113,74,240,106,29,151,7,255,216,121,159,216,121,159,216,121,159,88,28,238,131,95,142,53,109,119,79,84,185,5,152,204,83,244,76,191,137,75,87,202,113,74,240,106,29,151,7,255,216,121,159,216,121,159,216,121,159,88,28,176,250,120,212,9,226,159,198,24,206,234,168,167,215,178,99,159,197,60,226,130,194,9,219,192,128,204,60,255,255,255,255,216,121,128,255,216,121,159,26,29,205,101,0,26,29,205,101,0,159,88,28,216,144,108,165,199,186,18,74,4,7,163,45,171,55,178,200,43,19,179,220,217,17,30,66,148,13,206,164,69,85,83,68,67,120,255,255,216,121,128,255,130,88,57,0,238,131,95,142,53,109,119,79,84,185,5,152,204,83,244,76,191,137,75,87,202,113,74,240,106,29,151,7,176,250,120,212,9,226,159,198,24,206,234,168,167,215,178,99,159,197,60,226,130,194,9,219,192,128,204,60,130,27,0,0,0,1,247,68,36,54,162,88,28,69,223,95,39,75,137,80,181,18,176,141,16,101,104,100,149,134,89,196,236,243,255,173,9,46,246,48,36,162,68,85,83,68,114,27,0,1,198,61,165,135,102,108,69,115,85,83,68,114,26,69,244,39,7,88,28,216,144,108,165,199,186,18,74,4,7,163,45,171,55,178,200,43,19,179,220,217,17,30,66,148,13,206,164,162,69,85,83,68,67,120,27,0,1,198,60,40,74,53,64,72,0,20,223,16,85,83,68,77,26,237,210,145,128,2,26,0,2,201,1];
const REAL_SEAL_TXID: [u8;32] = [60,45,206,20,202,195,143,176,54,21,32,74,108,107,131,103,7,58,176,41,192,217,170,112,102,81,201,188,212,178,210,48]; const REAL_SEAL_IDX: u32 = 1;
// constructed seal-spend (Conway format): input=SEAL, output inline datum = commitment
const CON_BODY: &[u8] = &[163,0,217,1,2,129,130,88,32,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,7,1,129,163,0,88,29,96,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,1,26,0,30,132,128,2,130,1,216,24,88,32,64,106,127,177,14,22,46,9,139,203,250,129,196,114,83,169,145,60,86,36,100,168,239,234,109,8,184,68,124,188,41,95,2,26,0,2,152,16];
const CON_SEAL_TXID: [u8;32] = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31]; const CON_SEAL_IDX: u32 = 7;
const NEW_STATE: &[u8] = &[98,111,117,110,100,45,97,115,115,101,116,45,115,116,97,116,101,45,118,49,58,32,111,119,110,101,114,61,97,108,105,99,101,32,97,109,111,117,110,116,61,49,48,48,48];
const NEW_SEAL_TXID: [u8;32] = [9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9]; const NEW_SEAL_IDX: u32 = 0;

// ---- minimal CBOR reader ----
fn hdr(b: &[u8], i: usize) -> (u8, u64, usize) {   // (major, arg, next_index_after_header)
    let ib = b[i]; let major = ib >> 5; let lo = ib & 0x1f;
    match lo {
        0..=23 => (major, lo as u64, i+1),
        24 => (major, b[i+1] as u64, i+2),
        25 => (major, u16::from_be_bytes([b[i+1],b[i+2]]) as u64, i+3),
        26 => (major, u32::from_be_bytes([b[i+1],b[i+2],b[i+3],b[i+4]]) as u64, i+5),
        27 => (major, u64::from_be_bytes([b[i+1],b[i+2],b[i+3],b[i+4],b[i+5],b[i+6],b[i+7],b[i+8]]), i+9),
        _ => (major, 0, i+1),
    }
}
fn skip(b: &[u8], i: usize) -> usize {   // skip any one CBOR item
    let (m, arg, mut j) = hdr(b, i);
    match m {
        0 | 1 | 7 => j,                              // uint/nint/simple
        2 | 3 => j + arg as usize,                   // bytes/text
        4 => { for _ in 0..arg { j = skip(b, j); } j }      // array
        5 => { for _ in 0..arg { j = skip(b, j); j = skip(b, j); } j } // map
        6 => skip(b, j),                             // tag: skip tagged item
        _ => j,
    }
}
// parse body map -> (inputs as (txid,idx), output[0] inline-datum bytes)
fn parse_body(b: &[u8]) -> (Vec<([u8;32],u32)>, Vec<u8>) {
    let mut inputs: Vec<([u8;32],u32)> = Vec::new();
    let mut datum: Vec<u8> = Vec::new();
    let (m, n, mut i) = hdr(b, 0); if m != 5 { return (inputs, datum); }   // body must be a map
    for _ in 0..n {
        let (km, key, ki) = hdr(b, i); i = ki; let _ = km;
        if key == 0 {
            // inputs: optional tag 258, then array of [bytes32, uint]
            let (tm, targ, ti) = hdr(b, i);
            let mut j = if tm == 6 && targ == 258 { ti } else { i };
            let (_am, cnt, aj) = hdr(b, j); j = aj;
            for _ in 0..cnt {
                let (_pm, _two, pj) = hdr(b, j); j = pj;            // [txid, idx]
                let (_bm, blen, bj) = hdr(b, j);                    // bytes32
                let mut id=[0u8;32]; id.copy_from_slice(&b[bj..bj+blen as usize]); j = bj + blen as usize;
                let (_im, idx, ij) = hdr(b, j); j = ij;
                inputs.push((id, idx as u32));
            }
            i = j;
        } else if key == 1 {
            // outputs: array of maps; grab output[0]'s inline datum (key 2 = [1, tag24(bytes)])
            let (_om, ocnt, mut j) = hdr(b, i);
            for o in 0..ocnt {
                let (_mm, ents, mut k) = hdr(b, j);
                for _ in 0..ents {
                    let (_ekm, ekey, eki) = hdr(b, k); k = eki;
                    if ekey == 2 && o == 0 {
                        // datum_option = [1, tag24(bytes)]
                        let (_dm, _d2, da) = hdr(b, k);             // array len 2
                        let nk = skip(b, da);                      // skip the `1`
                        let (_tm2, _t24, ta) = hdr(b, nk);         // tag 24
                        let (_cm, clen, ca) = hdr(b, ta);          // bytes
                        datum.extend_from_slice(&b[ca..ca+clen as usize]);
                        k = ca + clen as usize;
                    } else { k = skip(b, k); }
                }
                j = k;
            }
            i = j;
        } else { i = skip(b, i); }
    }
    (inputs, datum)
}
fn b2b256(parts: &[&[u8]]) -> [u8;32] {
    let mut h = blake2b_ref::Blake2bBuilder::new(32).build();
    for p in parts { h.update(p); } let mut o=[0u8;32]; h.finalize(&mut o); o
}
fn consumes(inputs: &[([u8;32],u32)], txid: &[u8;32], idx: u32) -> bool {
    inputs.iter().any(|(t,i)| t==txid && *i==idx)
}
fn program_entry() -> i8 {
    let w = match load_witness_args(0, Source::GroupInput) { Ok(w)=>w, Err(_)=>return 1 };
    let lock = match w.lock().to_opt() { Some(l)=>l.raw_data(), None=>return 2 };
    let mode = if lock.is_empty() {0u8} else {lock[0]};
    if mode == 0 {
        // §6.2: parse the REAL Conway tx; the real seal input must be detected; datum extracted
        let (inputs, datum) = parse_body(REAL_BODY);
        if !consumes(&inputs, &REAL_SEAL_TXID, REAL_SEAL_IDX) { return 5; }  // seal not found in real tx
        if datum.is_empty() { return 6; }                                    // inline datum not extracted
        0
    } else {
        // §6.3: full BoundAsset transition on a constructed seal-spend
        let (inputs, commitment) = parse_body(CON_BODY);
        if !consumes(&inputs, &CON_SEAL_TXID, CON_SEAL_IDX) { return 7; }     // seal consumed?
        let expect = b2b256(&[NEW_STATE, &NEW_SEAL_TXID, &NEW_SEAL_IDX.to_le_bytes()]);
        if commitment.as_slice() != &expect[..] { return 8; }                // commitment binds new state?
        // (in production also: cardano_tx_is_certified(blake2b256(body)) - the proven oracle)
        0
    }
}
