//! Verify the REAL Mithril BLS-STM multi-signature on our burn's certificate (single-cert STM check -
//! the trustless reverse-leg crux) with the official mithril crates. This is the computation STARK-Mithril
//! arithmetizes; CKB-VM then verifies a succinct proof of it.
use mithril_client::ClientBuilder;
use mithril_common::entities::{Certificate, CertificateSignature};
use mithril_common::crypto_helper::ProtocolParameters as StmParameters;
const AGG: &str = "https://aggregator.testing-preview.api.mithril.network/aggregator";
const BURN: &str = "6608c4c828ceec5bb94c0973aeb41f5e04a85225a06edd90874b09d20515a800";
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let genesis = std::fs::read_to_string("/tmp/genesis.vkey")?.trim().to_string();
    let client = ClientBuilder::aggregator(AGG, &genesis).build()?;
    let proofs = client.cardano_transaction().get_proofs(&[BURN]).await?;
    let verified = proofs.verify()?;                          // tx Merkle inclusion proof verified
    eprintln!("tx-inclusion proof verified; cert {}", proofs.certificate_hash);
    let entity: Certificate = client.certificate().get(&proofs.certificate_hash).await?.expect("cert").try_into()?;
    let msig = match &entity.signature {
        CertificateSignature::MultiSignature(_, s) => s,
        _ => panic!("not a standard (multisig) certificate"),
    };
    let avk = entity.create_aggregate_verification_key();
    let params: StmParameters = entity.metadata.protocol_parameters.clone().into();
    msig.verify(entity.signed_message.as_bytes(), &avk, &params)?;   // <-- the BLS-STM aggregate check
    println!("STM_MULTISIG_VERIFIED true");
    println!("cert {} epoch {} params k={} m={} phi_f={}", proofs.certificate_hash, entity.epoch, params.k, params.m, params.phi_f);
    println!("certified_transactions {:?}", verified.certified_transactions());
    Ok(())
}
