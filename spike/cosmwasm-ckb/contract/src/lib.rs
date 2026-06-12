//! ckb-verifier — a CosmWasm contract that verifies the bridge's CKB-state Groth16 proof (BLS12-381), the
//! reverse leg of the Cosmos <-> CKB isomorphic binding (Cosmos verifies CKB). It checks the SAME proof
//! Cardano already verifies: e(A,B) == e(alpha,beta) * e(vk_x,gamma) * e(C,delta), with
//! vk_x = ic[0] + sum(pub_i * ic[i+1]). Compiles to wasm32 (the CosmWasm target) and verifies the real proof
//! in the unit test. Points are compressed hex (G1 48B, G2 96B); public inputs are 32-byte little-endian
//! scalar hex.
use bls12_381::{multi_miller_loop, G1Affine, G1Projective, G2Affine, G2Prepared, Gt, Scalar};
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{entry_point, to_json_binary, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdError, StdResult};

#[cw_serde]
pub struct InstantiateMsg {}

#[cw_serde]
pub enum QueryMsg {
    /// Verify a Groth16-BLS12-381 proof of CKB state. All points compressed hex; public_inputs are 32-byte LE.
    VerifyCkbProof {
        a: String, b: String, c: String,
        alpha: String, beta: String, gamma: String, delta: String,
        ic: Vec<String>, public_inputs: Vec<String>,
    },
}

#[cw_serde]
pub struct VerifyResp { pub valid: bool }

#[entry_point]
pub fn instantiate(_d: DepsMut, _e: Env, _i: MessageInfo, _m: InstantiateMsg) -> StdResult<Response> {
    Ok(Response::new())
}

#[entry_point]
pub fn query(_deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::VerifyCkbProof { a, b, c, alpha, beta, gamma, delta, ic, public_inputs } => {
            let valid = verify(&a, &b, &c, &alpha, &beta, &gamma, &delta, &ic, &public_inputs)
                .map_err(StdError::generic_err)?;
            to_json_binary(&VerifyResp { valid })
        }
    }
}

fn g1(h: &str) -> Result<G1Affine, String> {
    let arr: [u8; 48] = hex::decode(h.trim_start_matches("0x")).map_err(|_| "g1 hex")?.try_into().map_err(|_| "g1 len")?;
    Option::from(G1Affine::from_compressed(&arr)).ok_or_else(|| "g1 point".to_string())
}
fn g2(h: &str) -> Result<G2Affine, String> {
    let arr: [u8; 96] = hex::decode(h.trim_start_matches("0x")).map_err(|_| "g2 hex")?.try_into().map_err(|_| "g2 len")?;
    Option::from(G2Affine::from_compressed(&arr)).ok_or_else(|| "g2 point".to_string())
}
fn scalar(h: &str) -> Result<Scalar, String> {
    let arr: [u8; 32] = hex::decode(h.trim_start_matches("0x")).map_err(|_| "scalar hex")?.try_into().map_err(|_| "scalar len")?;
    Option::from(Scalar::from_bytes(&arr)).ok_or_else(|| "scalar".to_string()) // little-endian
}

/// Groth16 over BLS12-381: e(A,B) == e(alpha,beta) * e(vk_x,gamma) * e(C,delta).
pub fn verify(a: &str, b: &str, c: &str, alpha: &str, beta: &str, gamma: &str, delta: &str, ic: &[String], pubs: &[String]) -> Result<bool, String> {
    let a = g1(a)?; let b = g2(b)?; let c = g1(c)?;
    let alpha = g1(alpha)?; let beta = g2(beta)?; let gamma = g2(gamma)?; let delta = g2(delta)?;
    let ic: Vec<G1Affine> = ic.iter().map(|h| g1(h)).collect::<Result<_, _>>()?;
    if ic.len() != pubs.len() + 1 { return Err("ic/pubs length".into()); }
    let pubs: Vec<Scalar> = pubs.iter().map(|h| scalar(h)).collect::<Result<_, _>>()?;

    // vk_x = ic[0] + sum(pub_i * ic[i+1])
    let mut vk_x = G1Projective::from(ic[0]);
    for i in 0..pubs.len() { vk_x += G1Projective::from(ic[i + 1]) * pubs[i]; }
    let vk_x = G1Affine::from(vk_x);

    // e(A,B) * e(-vk_x, gamma) * e(-C, delta) * e(-alpha, beta) == 1
    let ml = multi_miller_loop(&[
        (&a, &G2Prepared::from(b)),
        (&(-vk_x), &G2Prepared::from(gamma)),
        (&(-c), &G2Prepared::from(delta)),
        (&(-alpha), &G2Prepared::from(beta)),
    ]);
    Ok(ml.final_exponentiation() == Gt::identity())
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::BigUint;

    #[test]
    fn verifies_real_ckb_state_proof() {
        let j: serde_json::Value = serde_json::from_str(include_str!("../../../ckb-to-cardano/circuit/ceremony/leap_bound_windowed_redeemer.json")).unwrap();
        let s = |v: &serde_json::Value| v.as_str().unwrap().to_string();
        let proof = &j["proof"]; let vk = &j["vk"];
        let ic: Vec<String> = vk["ic"].as_array().unwrap().iter().map(s).collect();
        // public inputs: decimal -> 32-byte little-endian hex
        let pubs: Vec<String> = j["public_inputs_dec"].as_array().unwrap().iter().map(|v| {
            let n = BigUint::parse_bytes(v.as_str().unwrap().as_bytes(), 10).unwrap();
            let mut le = n.to_bytes_le(); le.resize(32, 0);
            hex::encode(le)
        }).collect();
        let valid = verify(&s(&proof["a"]), &s(&proof["b"]), &s(&proof["c"]),
            &s(&vk["alpha_g1"]), &s(&vk["beta_g2"]), &s(&vk["gamma_g2"]), &s(&vk["delta_g2"]), &ic, &pubs).unwrap();
        assert!(valid, "the CKB-state proof should verify in the CosmWasm contract logic");

        // tampered public input must NOT verify (fail-closed)
        let mut bad = pubs.clone(); bad[0] = hex::encode([1u8; 32]);
        let invalid = verify(&s(&proof["a"]), &s(&proof["b"]), &s(&proof["c"]),
            &s(&vk["alpha_g1"]), &s(&vk["beta_g2"]), &s(&vk["gamma_g2"]), &s(&vk["delta_g2"]), &ic, &bad).unwrap();
        assert!(!invalid, "a tampered public input must be rejected");
    }
}
