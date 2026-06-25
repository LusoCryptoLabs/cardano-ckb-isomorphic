//! NETWORK-FREE Mithril verification from saved cert+proof JSON - this is exactly the computation a
//! zkVM guest (SP1/Risc0) proves for M2: given the certificate and the tx-inclusion proof bytes, verify
//! (1) the tx Merkle proof, (2) the BLS-STM aggregate multi-signature, (3) the proof binds to the cert.
//! No aggregator calls. Inputs are byte blobs => directly arithmetizable / zkVM-provable.
use mithril_common::messages::{CardanoTransactionsProofsMessage, CertificateMessage};
use mithril_common::entities::{Certificate, CertificateSignature};
use mithril_common::crypto_helper::ProtocolParameters as StmParameters;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proof_json = std::env::args().nth(1).unwrap_or("/tmp/mithril_proof.json".into());
    let cert_json  = std::env::args().nth(2).unwrap_or("../mithril_verify/cert.example.json".into());
    // ---- the guest's pure inputs: two byte blobs ----
    let pm: CardanoTransactionsProofsMessage = serde_json::from_reader(std::fs::File::open(&proof_json)?)?;
    let cm: CertificateMessage = serde_json::from_reader(std::fs::File::open(&cert_json)?)?;

    // (1) tx-inclusion Merkle proof (offline)
    let verified = pm.verify()?;
    // (3) the proof's certified set + cert hash binding
    assert_eq!(pm.certificate_hash, cm.hash, "proof/cert mismatch");
    // (2) BLS-STM aggregate multisig (offline)
    let cert: Certificate = cm.try_into()?;
    let msig = match &cert.signature {
        CertificateSignature::MultiSignature(_, s) => s,
        _ => panic!("not a standard certificate"),
    };
    let avk = cert.create_aggregate_verification_key();
    let params: StmParameters = cert.metadata.protocol_parameters.clone().into();
    msig.verify(cert.signed_message.as_bytes(), &avk, &params)?;

    println!("OFFLINE_STM_VERIFIED true (no network)");
    println!("cert {} epoch {}  certified {:?}", cert.hash, cert.epoch, verified.certified_transactions());
    Ok(())
}
