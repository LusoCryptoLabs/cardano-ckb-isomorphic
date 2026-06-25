//! SP1 guest: verify a CKB header chain inside the zkVM and commit the checkpoint it attests. The resulting
//! (core STARK) proof certifies that some valid PoW chain links `genesis_parent` to `tip_hash` with
//! `total_work` cumulative difficulty - without revealing the headers. Hash-based ⇒ post-quantum.
#![no_main]
sp1_zkvm::entrypoint!(main);

use ckb_chain_lib::{verify_chain, Header};

pub fn main() {
    // public statement
    let genesis_parent = sp1_zkvm::io::read::<[u8; 32]>();
    let compact_target = sp1_zkvm::io::read::<u32>();
    // private witness: the header chain
    let headers = sp1_zkvm::io::read::<Vec<Header>>();

    // verifies real Eaglesong PoW + compact-target difficulty + U256 cumulative work
    let summary = verify_chain(genesis_parent, compact_target, &headers).expect("invalid CKB header chain");

    // commit the public checkpoint: statement + attested result
    sp1_zkvm::io::commit(&genesis_parent);
    sp1_zkvm::io::commit(&compact_target);
    sp1_zkvm::io::commit(&summary.chain_root); // MMR root - the light-client commitment the checkpoint pins
    sp1_zkvm::io::commit(&summary.tip_hash);
    sp1_zkvm::io::commit(&summary.total_work); // [u8; 32] big-endian U256
    sp1_zkvm::io::commit(&summary.count);
}
