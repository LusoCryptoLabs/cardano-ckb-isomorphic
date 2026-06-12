//! ckb-verifier — a CosmWasm contract that verifies the bridge's CKB-state Groth16 proof (BLS12-381), the
//! reverse leg of the Cosmos <-> CKB isomorphic binding (Cosmos verifies CKB). It checks the SAME proof
//! Cardano already verifies: e(A,B) == e(alpha,beta) * e(vk_x,gamma) * e(C,delta), with
//! vk_x = ic[0] + sum(pub_i * ic[i+1]).
//!
//! Production form: the only in-wasm elliptic-curve work is computing vk_x (G1 scalar muls); the final
//! four-pairing check is delegated to CosmWasm 2.x's native `bls12_381_pairing_equality` host function, which
//! runs the chain's audited BLS implementation. That is smaller and far cheaper than doing the Miller loop and
//! final exponentiation in wasm. The original all-in-wasm equation is kept as a test-only reference
//! (`verify_inwasm`) and the unit test cross-checks the two against the real proof.
//!
//! Points are compressed hex (G1 48B, G2 96B); public inputs are 32-byte little-endian scalar hex.
use bls12_381::{G1Affine, G1Projective, Scalar};
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{entry_point, to_json_binary, Api, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdError, StdResult};

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
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::VerifyCkbProof { a, b, c, alpha, beta, gamma, delta, ic, public_inputs } => {
            let valid = verify(deps.api, &a, &b, &c, &alpha, &beta, &gamma, &delta, &ic, &public_inputs)
                .map_err(StdError::generic_err)?;
            to_json_binary(&VerifyResp { valid })
        }
    }
}

fn raw(h: &str, n: usize) -> Result<Vec<u8>, String> {
    let b = hex::decode(h.trim_start_matches("0x")).map_err(|_| "hex")?;
    if b.len() != n { return Err("point length".into()); }
    Ok(b)
}
fn g1(h: &str) -> Result<G1Affine, String> {
    let arr: [u8; 48] = raw(h, 48)?.try_into().map_err(|_| "g1 len")?;
    Option::from(G1Affine::from_compressed(&arr)).ok_or_else(|| "g1 point".to_string())
}
fn scalar(h: &str) -> Result<Scalar, String> {
    let arr: [u8; 32] = hex::decode(h.trim_start_matches("0x")).map_err(|_| "scalar hex")?.try_into().map_err(|_| "scalar len")?;
    Option::from(Scalar::from_bytes(&arr)).ok_or_else(|| "scalar".to_string()) // little-endian
}

/// vk_x = ic[0] + sum(pub_i * ic[i+1]), returned compressed (48 bytes). The only EC arithmetic done in wasm.
fn compute_vk_x(ic: &[String], pubs: &[String]) -> Result<[u8; 48], String> {
    if ic.len() != pubs.len() + 1 { return Err("ic/pubs length".into()); }
    let mut acc = G1Projective::from(g1(&ic[0])?);
    for i in 0..pubs.len() {
        acc += G1Projective::from(g1(&ic[i + 1])?) * scalar(&pubs[i])?;
    }
    Ok(G1Affine::from(acc).to_compressed())
}

/// Groth16 over BLS12-381, final pairing via the host function:
/// e(alpha,beta) * e(vk_x,gamma) * e(C,delta) == e(A,B).
/// ps (G1, 48B each) = alpha || vk_x || C ; qs (G2, 96B each) = beta || gamma || delta ; r = A ; s = B.
pub fn verify(api: &dyn Api, a: &str, b: &str, c: &str, alpha: &str, beta: &str, gamma: &str, delta: &str, ic: &[String], pubs: &[String]) -> Result<bool, String> {
    let vk_x = compute_vk_x(ic, pubs)?;
    let mut ps = Vec::with_capacity(48 * 3);
    ps.extend_from_slice(&raw(alpha, 48)?);
    ps.extend_from_slice(&vk_x);
    ps.extend_from_slice(&raw(c, 48)?);
    let mut qs = Vec::with_capacity(96 * 3);
    qs.extend_from_slice(&raw(beta, 96)?);
    qs.extend_from_slice(&raw(gamma, 96)?);
    qs.extend_from_slice(&raw(delta, 96)?);
    let r = raw(a, 48)?;
    let s = raw(b, 96)?;
    api.bls12_381_pairing_equality(&ps, &qs, &r, &s).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bls12_381::{multi_miller_loop, G2Affine, G2Prepared, Gt};
    use cosmwasm_std::testing::mock_dependencies;
    use num_bigint::BigUint;

    fn g2(h: &str) -> Result<G2Affine, String> {
        let arr: [u8; 96] = hex::decode(h.trim_start_matches("0x")).map_err(|_| "g2 hex")?.try_into().map_err(|_| "g2 len")?;
        Option::from(G2Affine::from_compressed(&arr)).ok_or_else(|| "g2 point".to_string())
    }

    /// The original all-in-wasm equation, kept as an independent reference to cross-check the host-fn refactor.
    fn verify_inwasm(a: &str, b: &str, c: &str, alpha: &str, beta: &str, gamma: &str, delta: &str, ic: &[String], pubs: &[String]) -> Result<bool, String> {
        let a = g1(a)?; let b = g2(b)?; let c = g1(c)?;
        let alpha = g1(alpha)?; let beta = g2(beta)?; let gamma = g2(gamma)?; let delta = g2(delta)?;
        if ic.len() != pubs.len() + 1 { return Err("ic/pubs length".into()); }
        let mut vk_x = G1Projective::from(g1(&ic[0])?);
        for i in 0..pubs.len() { vk_x += G1Projective::from(g1(&ic[i + 1])?) * scalar(&pubs[i])?; }
        let vk_x = G1Affine::from(vk_x);
        let ml = multi_miller_loop(&[
            (&a, &G2Prepared::from(b)),
            (&(-vk_x), &G2Prepared::from(gamma)),
            (&(-c), &G2Prepared::from(delta)),
            (&(-alpha), &G2Prepared::from(beta)),
        ]);
        Ok(ml.final_exponentiation() == Gt::identity())
    }

    struct Inputs { a: String, b: String, c: String, alpha: String, beta: String, gamma: String, delta: String, ic: Vec<String>, pubs: Vec<String> }
    fn load() -> Inputs {
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
        Inputs { a: s(&proof["a"]), b: s(&proof["b"]), c: s(&proof["c"]),
            alpha: s(&vk["alpha_g1"]), beta: s(&vk["beta_g2"]), gamma: s(&vk["gamma_g2"]), delta: s(&vk["delta_g2"]), ic, pubs }
    }

    #[test]
    fn verifies_real_ckb_state_proof_via_host_fn() {
        let deps = mock_dependencies();
        let i = load();
        let valid = verify(&deps.api, &i.a, &i.b, &i.c, &i.alpha, &i.beta, &i.gamma, &i.delta, &i.ic, &i.pubs).unwrap();
        assert!(valid, "the CKB-state proof should verify through the host pairing function");

        // tampered public input must NOT verify (fail-closed)
        let mut bad = i.pubs.clone(); bad[0] = hex::encode([1u8; 32]);
        let invalid = verify(&deps.api, &i.a, &i.b, &i.c, &i.alpha, &i.beta, &i.gamma, &i.delta, &i.ic, &bad).unwrap();
        assert!(!invalid, "a tampered public input must be rejected by the host pairing function");
    }

    #[test]
    fn host_fn_matches_inwasm_reference() {
        let deps = mock_dependencies();
        let i = load();
        // same input: host-fn path and all-in-wasm path must agree, both on the real proof and a tampered one.
        let host_ok = verify(&deps.api, &i.a, &i.b, &i.c, &i.alpha, &i.beta, &i.gamma, &i.delta, &i.ic, &i.pubs).unwrap();
        let wasm_ok = verify_inwasm(&i.a, &i.b, &i.c, &i.alpha, &i.beta, &i.gamma, &i.delta, &i.ic, &i.pubs).unwrap();
        assert_eq!(host_ok, wasm_ok, "host pairing and in-wasm pairing disagree on the real proof");
        assert!(host_ok);

        let mut bad = i.pubs.clone(); bad[0] = hex::encode([7u8; 32]);
        let host_bad = verify(&deps.api, &i.a, &i.b, &i.c, &i.alpha, &i.beta, &i.gamma, &i.delta, &i.ic, &bad).unwrap();
        let wasm_bad = verify_inwasm(&i.a, &i.b, &i.c, &i.alpha, &i.beta, &i.gamma, &i.delta, &i.ic, &bad).unwrap();
        assert_eq!(host_bad, wasm_bad, "host pairing and in-wasm pairing disagree on a tampered input");
        assert!(!host_bad);
    }
}
