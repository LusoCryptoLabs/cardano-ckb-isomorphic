//! Native CKB ChainRootMMR reference (HeaderDigest), for grounding + the gadget differential test.
//! HeaderDigest is a 120-byte molecule struct (LE numbers):
//!   children_hash[32] | total_difficulty[32] | start_number[8] end_number[8] |
//!   start_epoch[8] end_epoch[8] | start_timestamp[8] end_timestamp[8] |
//!   start_compact_target[4] end_compact_target[4]
//! mmr_hash = ckbhash(serialize(digest));  merge.children_hash = ckbhash(mmr_hash(l)||mmr_hash(r)),
//! difficulty summed, ranges taken from l(start)/r(end). The chain root committed in block.extension
//! = mmr_hash(bagged root). (We validate the mechanics on real headers; binding to the LIVE chain
//! root needs the light-client MMR proof, relayer-fetched - like Mithril proofs on the other leg.)
use blake2b_rs::Blake2bBuilder;
pub fn ckbhash(d:&[u8])->[u8;32]{ let mut h=Blake2bBuilder::new(32).personal(b"ckb-default-hash").build(); h.update(d); let mut o=[0u8;32]; h.finalize(&mut o); o }

pub type Digest = [u8;120];
pub fn mmr_hash(d:&Digest)->[u8;32]{ ckbhash(d) }

fn add256(a:&[u8],b:&[u8])->[u8;32]{ // little-endian wrapping add
    let mut o=[0u8;32]; let mut c=0u16;
    for i in 0..32 { let s=a[i] as u16 + b[i] as u16 + c; o[i]=s as u8; c=s>>8; }
    o
}
// difficulty = floor(2^256 / (target+1)); target big-endian 32 bytes. (metadata; consistency is
// AdvanceCKBCert's job, not per-leap membership.) Computed here just to populate the leaf faithfully.
pub fn leaf(header_hash:[u8;32], diff_le:[u8;32], number:u64, epoch:u64, ts:u64, compact:u32)->Digest{
    let mut d=[0u8;120];
    d[0..32].copy_from_slice(&header_hash);
    d[32..64].copy_from_slice(&diff_le);   // total_difficulty (LE) = compact_to_difficulty
    d[64..72].copy_from_slice(&number.to_le_bytes());
    d[72..80].copy_from_slice(&number.to_le_bytes());
    d[80..88].copy_from_slice(&epoch.to_le_bytes());
    d[88..96].copy_from_slice(&epoch.to_le_bytes());
    d[96..104].copy_from_slice(&ts.to_le_bytes());
    d[104..112].copy_from_slice(&ts.to_le_bytes());
    d[112..116].copy_from_slice(&compact.to_le_bytes());
    d[116..120].copy_from_slice(&compact.to_le_bytes());
    d
}
pub fn merge(l:&Digest,r:&Digest)->Digest{
    let mut d=[0u8;120];
    let ch=ckbhash(&[mmr_hash(l).as_slice(), mmr_hash(r).as_slice()].concat());
    d[0..32].copy_from_slice(&ch);
    d[32..64].copy_from_slice(&add256(&l[32..64], &r[32..64]));
    d[64..72].copy_from_slice(&l[64..72]);    // start_number from l
    d[72..80].copy_from_slice(&r[72..80]);    // end_number from r
    d[80..88].copy_from_slice(&l[80..88]); d[88..96].copy_from_slice(&r[88..96]);
    d[96..104].copy_from_slice(&l[96..104]); d[104..112].copy_from_slice(&r[104..112]);
    d[112..116].copy_from_slice(&l[112..116]); d[116..120].copy_from_slice(&r[116..120]);
    d
}

// ---- height-indexed peak array (general MMR), for variable-carry append + batching ----
/// peaks[h] = Some(digest) iff bit h of the current leaf_count is set.
pub fn append(peaks: &mut Vec<Option<Digest>>, leaf: Digest) {
    let mut carry = leaf; let mut h = 0;
    loop {
        if h >= peaks.len() { peaks.push(None); }
        match peaks[h] {
            Some(p) => { carry = merge(&p, &carry); peaks[h] = None; h += 1; }
            None => { peaks[h] = Some(carry); break; }
        }
    }
}
/// bag peaks low->high: acc = merge(higher_peak, acc) (matches CKB bag_rl). Returns the root digest.
pub fn bag(peaks: &[Option<Digest>]) -> Option<Digest> {
    let mut acc: Option<Digest> = None;
    for h in 0..peaks.len() {
        if let Some(p) = peaks[h] { acc = Some(match acc { None => p, Some(a) => merge(&p, &a) }); }
    }
    acc
}
pub fn build(leaves: &[Digest]) -> Vec<Option<Digest>> {
    let mut peaks = Vec::new();
    for l in leaves { append(&mut peaks, *l); }
    peaks
}
