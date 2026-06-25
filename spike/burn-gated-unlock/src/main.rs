//! burn_gated_unlock.rs - a CKB LOCK script: the locked CKB is released ONLY if a Mithril-certified
//! Cardano BURN of the bridged asset is proven in-VM. It reads the certified tx-set root from a
//! light-client checkpoint cellDep ("LCKP"||root) and verifies the two-level Blake2s256 MKMapProof that
//! the burn tx 6608c4c8.. is under that root. No operator key authorizes the spend - a real certified
//! burn does. (The specific burn tx 6608c4c8 burned the full 100k-ckCKB supply, so gating on it binds
//! the amount; parsing arbitrary Conway burn amounts in-VM is the further generalization.)
#![no_std]
#![no_main]
use alloc::{vec, vec::Vec};
use ckb_std::ckb_constants::Source;
use ckb_std::high_level::{load_cell_data, load_cell_type_hash};
use ckb_std::error::SysError;
// the authenticated tx-set checkpoint's TYPE-SCRIPT HASH (TxSetCert verifier, data1, no args). Only a
// checkpoint cell carrying THIS type script is trusted (its root was cert-verified in-VM). Using the
// type-hash syscall avoids molecule Script decoding (which emits an instruction CKB-VM rejects).
const EXPECTED_TYPE_HASH: [u8;32] = [105,180,67,198,253,53,197,162,136,219,0,246,229,138,127,172,13,54,167,239,77,30,207,77,161,109,140,228,107,170,162,171];
use blake2::{Blake2s256, Digest};
use ckb_merkle_mountain_range::{MerkleProof, Merge, Result as MMRResult};
ckb_std::entry!(program_entry);
ckb_std::default_alloc!();

const TX_LEAF: &[u8] = &[54,54,48,56,99,52,99,56,50,56,99,101,101,99,53,98,98,57,52,99,48,57,55,51,97,101,98,52,49,102,53,101,48,52,97,56,53,50,50,53,97,48,54,101,100,100,57,48,56,55,52,98,48,57,100,50,48,53,49,53,97,56,48,48];        // ascii of burn tx 6608c4c8..
const SUB_ROOT: &[u8] = &[208,230,100,114,104,197,170,219,152,42,217,156,150,125,53,231,57,210,33,113,94,13,54,27,181,184,216,85,133,57,237,105];
const SUB_ITEMS: &[&[u8]] = &[&[57,98,102,97,100,98,57,102,55,51,52,102,54,51,99,98,57,102,98,49,101,97,52,98,51,98,48,52,56,57,97,50,52,57,101,54,54,99,54,53,51,54,49,102,52,51,99,56,53,97,54,49,52,100,56,57,53,101,97,99,98,48,102,48],&[89,150,250,63,175,184,83,123,235,65,33,138,151,113,159,207,26,206,125,213,8,93,225,239,133,145,201,4,40,119,30,151],&[63,97,33,34,130,18,225,235,214,137,214,224,239,130,163,181,68,190,151,73,40,39,192,127,146,16,211,45,0,162,246,214],&[107,57,169,115,16,165,160,117,129,120,21,217,211,24,111,107,227,130,125,65,222,0,157,21,185,79,235,114,248,110,153,182]];
const SUB_POS: u64 = 1; const SUB_SIZE: u64 = 19;
const RANGE_KEY: &[u8] = &[52,51,53,55,49,52,48,45,52,51,53,55,49,53,53];
const EXPECT_CERT_ROOT: &[u8] = &[238,4,128,83,232,156,197,8,20,223,55,176,124,181,133,5,223,208,125,192,102,237,93,195,195,182,31,95,239,255,213,25];   // ee048053.. (must match the checkpoint cellDep)
const MASTER_ITEMS: &[&[u8]] = &[&[14,123,184,30,79,192,130,102,138,133,139,173,80,150,22,244,51,130,105,49,134,98,211,185,171,37,173,188,43,195,187,230],&[210,250,214,242,183,119,80,228,209,67,149,33,103,145,99,134,75,127,201,152,55,235,29,84,176,1,229,116,84,62,88,16],&[189,215,119,68,109,203,153,108,61,84,194,255,225,136,83,234,76,48,235,67,96,141,223,68,201,159,99,33,22,104,219,108],&[53,37,176,173,254,152,237,23,195,46,199,164,7,207,232,195,170,93,82,242,28,139,132,163,103,96,2,193,19,104,196,146],&[243,4,147,50,37,31,79,64,201,104,232,77,178,180,23,132,235,60,191,190,119,232,166,51,234,137,62,137,165,28,139,65],&[156,22,217,114,131,35,89,110,81,112,206,75,163,50,163,95,206,15,98,89,101,99,81,178,57,208,183,126,14,54,69,107],&[147,108,75,93,23,15,109,10,161,166,111,94,193,45,194,132,54,137,161,186,79,173,64,227,79,14,181,56,140,228,31,255],&[224,238,72,170,197,232,65,27,15,215,87,232,100,234,231,236,138,46,17,142,219,124,47,211,124,205,188,144,85,19,152,104],&[171,135,115,96,237,212,93,90,252,230,229,151,242,86,187,235,39,113,59,166,222,249,131,201,79,55,90,202,15,47,34,7],&[235,135,233,220,232,172,3,59,9,247,107,139,8,199,5,18,197,176,37,199,44,108,223,163,4,252,204,16,79,150,1,96]];
const MASTER_POS: u64 = 567728; const MASTER_SIZE: u64 = 567730;

#[derive(Clone, PartialEq, Eq, Debug)]
struct Node(Vec<u8>);
struct MergeB2s;
impl Merge for MergeB2s {
    type Item = Node;
    fn merge(l: &Node, r: &Node) -> MMRResult<Node> {
        let mut h = Blake2s256::new(); h.update(&l.0); h.update(&r.0); Ok(Node(h.finalize().to_vec()))
    }
}
fn b2s(parts: &[&[u8]]) -> Vec<u8> {
    let mut h = Blake2s256::new(); for p in parts { h.update(p); } h.finalize().to_vec()
}

// Find the AUTHENTICATED light-client checkpoint among the cellDeps: data == "LCKP" || cert_root(32B)
// AND the cell carries the TxSetCert type script (so the root was cert-verified in-VM, not hand-supplied).
fn cert_root_from_checkpoint() -> Option<Vec<u8>> {
    let mut i = 0usize;
    loop {
        match load_cell_data(i, Source::CellDep) {
            Ok(data) => {
                if data.len() >= 36 && &data[0..4] == b"LCKP" {
                    if let Ok(Some(th)) = load_cell_type_hash(i, Source::CellDep) {
                        if th == EXPECTED_TYPE_HASH {
                            return Some(data[4..36].to_vec());
                        }
                    }
                }
                i += 1;
            }
            Err(SysError::IndexOutOfBound) => return None,
            Err(_) => return None,
        }
    }
}

pub fn program_entry() -> i8 {
    // 1. the certified Cardano tx-set root comes from an (authenticated) checkpoint cellDep
    let cert_root = match cert_root_from_checkpoint() { Some(r) => r, None => return 10 };
    // SEC C5: enforce the authenticated checkpoint root is the one this embedded burn proof was built for
    // (was a dead `let _ = EXPECT_CERT_ROOT;`). Checked before `cert_root` is consumed by the proof verify.
    if cert_root != EXPECT_CERT_ROOT.to_vec() { return 7; }
    // 2. sub-proof: the burn tx (ascii) is under SUB_ROOT (MMR over the block-range's txs)
    let sub_items: Vec<Node> = SUB_ITEMS.iter().map(|x| Node(x.to_vec())).collect();
    let sub_ok = MerkleProof::<Node, MergeB2s>::new(SUB_SIZE, sub_items)
        .verify(Node(SUB_ROOT.to_vec()), vec![(SUB_POS, Node(TX_LEAF.to_vec()))]).unwrap_or(false);
    if !sub_ok { return 5; }
    // 3. master proof: blake2s(range_key || sub_root) is under cert_root (the checkpoint's certified root)
    let master_leaf = Node(b2s(&[RANGE_KEY, SUB_ROOT]));
    let master_items: Vec<Node> = MASTER_ITEMS.iter().map(|x| Node(x.to_vec())).collect();
    let master_ok = MerkleProof::<Node, MergeB2s>::new(MASTER_SIZE, master_items)
        .verify(Node(cert_root), vec![(MASTER_POS, master_leaf)]).unwrap_or(false);
    if !master_ok { return 6; }
    0  // the certified burn is proven -> release the locked CKB
}
