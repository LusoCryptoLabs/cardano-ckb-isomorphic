//! M2 guest (relation M1): prove signed_message = Sha256( concat over ordered protocol-message parts of
//! key_bytes||value_bytes ) - exactly Mithril's ProtocolMessage::compute_hash. Public output = the digest.
#![no_main]
sp1_zkvm::entrypoint!(main);
use sha2::{Sha256, Digest};
pub fn main() {
    // input: the ordered (key, value) message parts
    let parts: Vec<(String, String)> = sp1_zkvm::io::read();
    let mut h = Sha256::new();
    for (k, v) in &parts {
        h.update(k.as_bytes());
        h.update(v.as_bytes());
    }
    let digest: [u8; 32] = h.finalize().into();
    sp1_zkvm::io::commit(&digest);   // public: the Mithril signed_message
}
