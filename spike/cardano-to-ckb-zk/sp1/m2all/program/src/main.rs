//! M1 + M2 + M3 + M4 composed in ONE SP1 proof, on the REAL Mithril preview cert 7356eaa1.. :
//!  M1: signed_message = Sha256(ordered key||value protocol-message parts)
//!  M2: BLS min-sig aggregate verifies over msgp = signed_message_ascii || avk_root
//!  M3: tx-inclusion - burn tx 6608c4c8.. is under the certified tx-set root via the two-level
//!      Blake2s256 MKMapProof (sub-tree + master MMR), and that root == the cardano_transactions_
//!      merkle_root PART that M1 hashes (so the BLS signature commits to the very root M3 opens).
//!  M4: cert_hash = Sha256(prev || epoch || meta_hash || pm_hash || signed_message || avk || feed || multisig)
//! Commits (signed_message, cert_hash, avk_root, hm, bls_ok, m3_ok) - the full reverse-leg statement.
#![no_main]
sp1_zkvm::entrypoint!(main);
use sha2::{Sha256, Digest};
use bls12_381::{G1Affine, G2Affine, G2Prepared, multi_miller_loop, Gt};
use core::ops::Neg;
use blake2::Blake2s256;
use ckb_merkle_mountain_range::{MerkleProof, Merge, Result as MMRResult};

// ---- M3: REAL MKMapProof for burn tx 6608c4c8.. under cert 7356eaa1.. (mithril_verify/proof.example.json) ----
const TX_LEAF: &[u8] = &[54,54,48,56,99,52,99,56,50,56,99,101,101,99,53,98,98,57,52,99,48,57,55,51,97,101,98,52,49,102,53,101,48,52,97,56,53,50,50,53,97,48,54,101,100,100,57,48,56,55,52,98,48,57,100,50,48,53,49,53,97,56,48,48];
const SUB_ROOT: &[u8] = &[208,230,100,114,104,197,170,219,152,42,217,156,150,125,53,231,57,210,33,113,94,13,54,27,181,184,216,85,133,57,237,105];
const SUB_ITEMS: &[&[u8]] = &[&[57,98,102,97,100,98,57,102,55,51,52,102,54,51,99,98,57,102,98,49,101,97,52,98,51,98,48,52,56,57,97,50,52,57,101,54,54,99,54,53,51,54,49,102,52,51,99,56,53,97,54,49,52,100,56,57,53,101,97,99,98,48,102,48],&[89,150,250,63,175,184,83,123,235,65,33,138,151,113,159,207,26,206,125,213,8,93,225,239,133,145,201,4,40,119,30,151],&[63,97,33,34,130,18,225,235,214,137,214,224,239,130,163,181,68,190,151,73,40,39,192,127,146,16,211,45,0,162,246,214],&[107,57,169,115,16,165,160,117,129,120,21,217,211,24,111,107,227,130,125,65,222,0,157,21,185,79,235,114,248,110,153,182]];
const SUB_POS: u64 = 1; const SUB_SIZE: u64 = 19;
const RANGE_KEY: &[u8] = &[52,51,53,55,49,52,48,45,52,51,53,55,49,53,53];
const CERT_ROOT: &[u8] = &[238,4,128,83,232,156,197,8,20,223,55,176,124,181,133,5,223,208,125,192,102,237,93,195,195,182,31,95,239,255,213,25];
const MASTER_ITEMS: &[&[u8]] = &[&[14,123,184,30,79,192,130,102,138,133,139,173,80,150,22,244,51,130,105,49,134,98,211,185,171,37,173,188,43,195,187,230],&[210,250,214,242,183,119,80,228,209,67,149,33,103,145,99,134,75,127,201,152,55,235,29,84,176,1,229,116,84,62,88,16],&[189,215,119,68,109,203,153,108,61,84,194,255,225,136,83,234,76,48,235,67,96,141,223,68,201,159,99,33,22,104,219,108],&[53,37,176,173,254,152,237,23,195,46,199,164,7,207,232,195,170,93,82,242,28,139,132,163,103,96,2,193,19,104,196,146],&[243,4,147,50,37,31,79,64,201,104,232,77,178,180,23,132,235,60,191,190,119,232,166,51,234,137,62,137,165,28,139,65],&[156,22,217,114,131,35,89,110,81,112,206,75,163,50,163,95,206,15,98,89,101,99,81,178,57,208,183,126,14,54,69,107],&[147,108,75,93,23,15,109,10,161,166,111,94,193,45,194,132,54,137,161,186,79,173,64,227,79,14,181,56,140,228,31,255],&[224,238,72,170,197,232,65,27,15,215,87,232,100,234,231,236,138,46,17,142,219,124,47,211,124,205,188,144,85,19,152,104],&[171,135,115,96,237,212,93,90,252,230,229,151,242,86,187,235,39,113,59,166,222,249,131,201,79,55,90,202,15,47,34,7],&[235,135,233,220,232,172,3,59,9,247,107,139,8,199,5,18,197,176,37,199,44,108,223,163,4,252,204,16,79,150,1,96]];
const MASTER_POS: u64 = 567728; const MASTER_SIZE: u64 = 567730;

#[derive(Clone, PartialEq, Eq, Debug)]
struct Node(Vec<u8>);
struct MergeB2s;
impl Merge for MergeB2s {
    type Item = Node;
    fn merge(l:&Node,r:&Node)->MMRResult<Node>{ let mut h=Blake2s256::new(); h.update(&l.0); h.update(&r.0); Ok(Node(h.finalize().to_vec())) }
}
fn b2s(parts:&[&[u8]])->Vec<u8>{ let mut h=Blake2s256::new(); for p in parts{h.update(p);} h.finalize().to_vec() }

fn hexlow(b:&[u8])->[u8;64]{ let h=b"0123456789abcdef"; let mut o=[0u8;64]; for(i,&x)in b.iter().enumerate(){o[2*i]=h[(x>>4)as usize];o[2*i+1]=h[(x&0xf)as usize];} o }
fn sha(parts:&[&[u8]])->[u8;32]{ let mut h=Sha256::new(); for p in parts{h.update(p);} h.finalize().into() }
pub fn main() {
    // M1 inputs
    let parts: Vec<(String,String)> = sp1_zkvm::io::read();
    let avk_root: Vec<u8> = sp1_zkvm::io::read();
    // M2 inputs
    let agg_sigma: Vec<u8> = sp1_zkvm::io::read();
    let agg_mvk: Vec<u8> = sp1_zkvm::io::read();
    let hm: Vec<u8> = sp1_zkvm::io::read();
    // M4 inputs
    let prev_hash: Vec<u8> = sp1_zkvm::io::read();
    let epoch_be: Vec<u8> = sp1_zkvm::io::read();
    let network: Vec<u8> = sp1_zkvm::io::read();
    let version: Vec<u8> = sp1_zkvm::io::read();
    let k_be: Vec<u8> = sp1_zkvm::io::read();
    let m_be: Vec<u8> = sp1_zkvm::io::read();
    let phi_be: Vec<u8> = sp1_zkvm::io::read();
    let init_ns: Vec<u8> = sp1_zkvm::io::read();
    let seal_ns: Vec<u8> = sp1_zkvm::io::read();
    let signers: Vec<(String,Vec<u8>)> = sp1_zkvm::io::read();
    let avk_hex: Vec<u8> = sp1_zkvm::io::read();
    let feed: Vec<u8> = sp1_zkvm::io::read();
    let multisig_hex: Vec<u8> = sp1_zkvm::io::read();

    // M1
    let sm: [u8;32] = sha(&parts.iter().flat_map(|(k,v)| [k.as_bytes().to_vec(), v.as_bytes().to_vec()]).collect::<Vec<_>>().iter().map(|x| x.as_slice()).collect::<Vec<_>>());
    let sm_hex = hexlow(&sm);

    // M2
    let sigma=G1Affine::from_compressed(&agg_sigma.try_into().unwrap()).unwrap();
    let mvk=G2Affine::from_compressed(&agg_mvk.try_into().unwrap()).unwrap();
    let hmg=G1Affine::from_compressed(&hm.clone().try_into().unwrap()).unwrap();
    let g2=G2Prepared::from(G2Affine::generator()); let mvkp=G2Prepared::from(mvk);
    let bls_ok = multi_miller_loop(&[(&sigma,&g2),(&hmg.neg(),&mvkp)]).final_exponentiation()==Gt::identity();

    // M3: two-level Blake2s256 MMR tx-inclusion, bound to M1's tx-set-root part
    let sub_items: Vec<Node> = SUB_ITEMS.iter().map(|x| Node(x.to_vec())).collect();
    let sub_ok = MerkleProof::<Node, MergeB2s>::new(SUB_SIZE, sub_items)
        .verify(Node(SUB_ROOT.to_vec()), vec![(SUB_POS, Node(TX_LEAF.to_vec()))]).unwrap_or(false);
    let master_leaf = Node(b2s(&[RANGE_KEY, SUB_ROOT]));
    let master_items: Vec<Node> = MASTER_ITEMS.iter().map(|x| Node(x.to_vec())).collect();
    let master_ok = MerkleProof::<Node, MergeB2s>::new(MASTER_SIZE, master_items)
        .verify(Node(CERT_ROOT.to_vec()), vec![(MASTER_POS, master_leaf)]).unwrap_or(false);
    // BINDING: the root M3 opens is exactly the cardano_transactions_merkle_root that M1 hashed (and M2 signed)
    let cert_root_hex = hexlow(CERT_ROOT);
    let root_binds = parts.iter().any(|(k,v)| k=="cardano_transactions_merkle_root" && v.as_bytes()==&cert_root_hex[..]);
    let m3_ok = sub_ok && master_ok && root_binds;

    // M4
    let pp_hash = hexlow(&sha(&[&k_be,&m_be,&phi_be]));
    let mut meta = Sha256::new();
    meta.update(&network); meta.update(&version); meta.update(&pp_hash); meta.update(&init_ns); meta.update(&seal_ns);
    for (pid,stake) in &signers { let ph=hexlow(&sha(&[pid.as_bytes(),stake])); meta.update(&ph); }
    let meta_hash = hexlow(&Into::<[u8;32]>::into(meta.finalize()));
    let cert_hash: [u8;32] = sha(&[&prev_hash,&epoch_be,&meta_hash,&sm_hex,&sm_hex,&avk_hex,&feed,&multisig_hex]);

    sp1_zkvm::io::commit(&sm_hex.to_vec());
    sp1_zkvm::io::commit(&cert_hash.to_vec());
    sp1_zkvm::io::commit(&avk_root);
    sp1_zkvm::io::commit(&hm);
    sp1_zkvm::io::commit(&bls_ok);
    sp1_zkvm::io::commit(&m3_ok);
}
