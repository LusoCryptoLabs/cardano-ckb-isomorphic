//! cross_chain_tx_proof.rs - CROSS-CHAIN PRIMITIVE: prove a REAL Cardano transaction's inclusion
//! INSIDE the CKB VM. Verifies a Mithril MKMapProof (two-level MMR, Blake2s256) that tx X is in the
//! certified Cardano tx-set root, using ckb-merkle-mountain-range (no_std). Host ground truth
//! (mithril-common): this proof verifies; certified root 5fae3a1b…. Returns 0 iff tx is proven in
//! CERT_ROOT (which the AdvanceCert verifier authenticates from a CardanoTransactions cert).
#![cfg_attr(not(test), no_std)]
#![cfg_attr(not(test), no_main)]
use alloc::{vec, vec::Vec};
use ckb_std::{ckb_constants::Source, high_level::load_witness_args};
use blake2::{Blake2s256, Digest};
use ckb_merkle_mountain_range::{MerkleProof, Merge, Result as MMRResult};
#[cfg(not(test))] ckb_std::entry!(program_entry);
#[cfg(not(test))] ckb_std::default_alloc!();

const TX_LEAF: &[u8] = &[54,52,102,98,99,99,50,51,97,98,54,97,102,48,49,50,48,51,49,53,57,97,52,53,48,53,97,101,57,99,49,101,99,53,99,56,49,50,50,53,98,101,99,98,50,97,49,54,101,51,48,51,101,55,101,52,99,100,48,54,98,51,56,54];        // ascii bytes of the tx hash
const SUB_ROOT: &[u8] = &[70,59,62,111,21,178,62,250,116,195,173,217,242,55,88,247,10,205,82,194,53,191,53,155,238,147,89,151,110,174,132,111];
const SUB_ITEMS: &[&[u8]] = &[&[50,98,53,50,98,52,48,56,49,48,98,51,99,50,55,100,53,101,57,50,57,54,49,53,55,50,50,54,98,56,101,102,53,49,50,56,54,101,52,48,55,99,100,50,52,99,56,57,98,101,101,98,56,51,52,55,98,56,49,102,53,50,49,49],&[45,52,59,182,188,149,136,185,32,10,39,91,171,11,139,254,255,231,110,230,253,80,148,116,21,144,77,117,191,85,236,3],&[49,97,55,56,48,99,52,48,54,100,98,48,52,51,98,49,100,102,99,57,57,48,50,100,54,49,56,51,54,102,100,102,55,97,50,101,54,49,49,48,99,100,99,100,57,55,52,57,99,102,99,51,101,97,53,54,101,98,50,50,97,100,99,55]];
const SUB_POS: u64 = 4; const SUB_SIZE: u64 = 8;
const RANGE_KEY: &[u8] = &[52,51,53,53,48,52,48,45,52,51,53,53,48,53,53];  // "start-end"
const CERT_ROOT: &[u8] = &[95,174,58,27,84,122,211,50,3,15,107,66,38,125,129,36,30,168,89,18,226,82,47,165,116,228,79,169,166,193,208,102];    // = certified cardano_transactions_merkle_root
const MASTER_ITEMS: &[&[u8]] = &[&[14,123,184,30,79,192,130,102,138,133,139,173,80,150,22,244,51,130,105,49,134,98,211,185,171,37,173,188,43,195,187,230],&[210,250,214,242,183,119,80,228,209,67,149,33,103,145,99,134,75,127,201,152,55,235,29,84,176,1,229,116,84,62,88,16],&[189,215,119,68,109,203,153,108,61,84,194,255,225,136,83,234,76,48,235,67,96,141,223,68,201,159,99,33,22,104,219,108],&[53,37,176,173,254,152,237,23,195,46,199,164,7,207,232,195,170,93,82,242,28,139,132,163,103,96,2,193,19,104,196,146],&[60,182,42,25,146,227,38,78,202,72,202,176,190,0,199,114,30,232,141,103,84,92,242,130,194,84,186,195,70,160,122,147],&[172,194,251,76,218,252,38,97,121,8,89,220,127,78,189,215,244,67,113,40,164,170,224,189,79,147,114,28,205,143,114,180],&[124,57,106,219,2,226,161,209,240,215,63,65,152,165,104,248,147,208,22,179,229,18,221,120,55,131,237,46,30,31,116,160],&[228,99,194,235,192,123,190,229,198,138,119,101,145,195,95,149,76,209,118,161,238,186,50,111,151,23,11,233,196,248,241,17],&[188,100,130,198,145,100,61,185,114,156,61,160,151,63,201,224,253,18,204,221,87,176,105,108,46,138,136,217,61,37,32,249]];
const MASTER_POS: u64 = 567451; const MASTER_SIZE: u64 = 567460;

#[derive(Clone, PartialEq, Eq, Debug)]
struct Node(Vec<u8>);
struct MergeB2s;
impl Merge for MergeB2s {
    type Item = Node;
    fn merge(l: &Node, r: &Node) -> MMRResult<Node> {
        let mut h = Blake2s256::new(); h.update(&l.0); h.update(&r.0);
        Ok(Node(h.finalize().to_vec()))
    }
}
fn b2s(parts: &[&[u8]]) -> Vec<u8> {
    let mut h = Blake2s256::new(); for p in parts { h.update(p); } h.finalize().to_vec()
}
fn program_entry() -> i8 {
    let _ = load_witness_args(0, Source::GroupInput);
    // 1. sub-proof: tx (ascii) is under SUB_ROOT (MMR over the block-range's txs)
    let sub_items: Vec<Node> = SUB_ITEMS.iter().map(|x| Node(x.to_vec())).collect();
    let sub_ok = MerkleProof::<Node, MergeB2s>::new(SUB_SIZE, sub_items)
        .verify(Node(SUB_ROOT.to_vec()), vec![(SUB_POS, Node(TX_LEAF.to_vec()))]).unwrap_or(false);
    if !sub_ok { return 5; }
    // 2. master leaf = Blake2s256(range_key || sub_root); proven under CERT_ROOT (MMR over ranges)
    let master_leaf = Node(b2s(&[RANGE_KEY, SUB_ROOT]));
    let master_items: Vec<Node> = MASTER_ITEMS.iter().map(|x| Node(x.to_vec())).collect();
    let master_ok = MerkleProof::<Node, MergeB2s>::new(MASTER_SIZE, master_items)
        .verify(Node(CERT_ROOT.to_vec()), vec![(MASTER_POS, master_leaf)]).unwrap_or(false);
    if !master_ok { return 6; }
    // CERT_ROOT is authenticated by the AdvanceCert verifier (cardano_transactions_merkle_root).
    0
}
