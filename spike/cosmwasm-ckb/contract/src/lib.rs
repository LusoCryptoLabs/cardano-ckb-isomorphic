//! ckb-verifier — a CosmWasm contract that verifies the bridge's CKB-state Groth16 proof (BLS12-381), the
//! reverse leg of the Cosmos <-> CKB isomorphic binding (Cosmos verifies CKB). It checks the SAME proof
//! Cardano already verifies: e(A,B) == e(alpha,beta) * e(vk_x,gamma) * e(C,delta), with
//! vk_x = ic[0] + sum(pub_i * ic[i+1]).
//!
//! Two query paths:
//!   * `VerifyCkbProof` takes the 5 public inputs as raw scalars and verifies the proof (the bare check).
//!   * `VerifyCkbEvent` takes the CONCRETE CKB event (window_root, seal, amount, recipient, tip_height, K) and
//!     DERIVES the 5 public inputs exactly as the leap circuit does, then verifies. This is what makes the
//!     contract a real bridge gate: it is bound to a named CKB event (a specific value to a specific recipient,
//!     spent at a specific seal under a specific checkpoint), not just "some valid proof exists". A relayer
//!     cannot present a valid proof and then claim different public inputs.
//!
//! Production form: the only in-wasm elliptic-curve work is computing vk_x (G1 scalar muls); the final
//! four-pairing check is delegated to CosmWasm 2.x's native `bls12_381_pairing_equality` host function, which
//! runs the chain's audited BLS implementation.
//!
//! Encodings (matching `leap_bound_windowed.rs`): pi[0]=LEmod(window_root[32]), pi[1]=LEmod(seal[32]),
//! pi[2]=LEmod(blake2b256(amount[16 LE] ‖ recipient[28] ‖ seal[32])), pi[3]=tip_height(u64), pi[4]=K(u64).
//! LEmod(b) = (b read little-endian) mod r (the BLS12-381 scalar order). Curve points are compressed hex
//! (G1 48B, G2 96B); raw public inputs (VerifyCkbProof) are 32-byte little-endian scalar hex.
use bls12_381::{G1Affine, G1Projective, Scalar};
use blake2::digest::{Update, VariableOutput};
use blake2::Blake2bVar;
use cosmwasm_schema::cw_serde;
#[allow(deprecated)]
use cosmwasm_std::CosmosMsg;
use cosmwasm_std::{entry_point, to_json_binary, Api, BankMsg, Binary, CanonicalAddr, Coin, Deps, DepsMut, Env, MessageInfo, Response, StdError, StdResult, Uint128};

#[cw_serde]
pub struct InstantiateMsg {}

#[cw_serde]
pub struct Vk {
    pub alpha: String, pub beta: String, pub gamma: String, pub delta: String, pub ic: Vec<String>,
}
#[cw_serde]
pub struct Proof { pub a: String, pub b: String, pub c: String }

#[cw_serde]
pub enum QueryMsg {
    /// Verify a Groth16-BLS12-381 proof against raw public inputs. All points compressed hex; public_inputs
    /// are 32-byte LE scalar hex.
    VerifyCkbProof {
        a: String, b: String, c: String,
        alpha: String, beta: String, gamma: String, delta: String,
        ic: Vec<String>, public_inputs: Vec<String>,
    },
    /// Verify a Groth16-BLS12-381 proof bound to a CONCRETE CKB event: the 5 public inputs are DERIVED from the
    /// event fields in-contract, so the proof is tied to this exact (window_root, seal, amount, recipient,
    /// tip_height, K). window_root/seal are 32-byte hex, recipient 28-byte hex, amount a u128.
    VerifyCkbEvent {
        window_root: String, seal: String, amount: Uint128, recipient: String, tip_height: u64, k: u64,
        proof: Proof, vk: Vk,
    },
}

#[cw_serde]
pub enum ExecuteMsg {
    /// Verify a CKB event proof and record its seal in the replay-once registry, so the SAME CKB event cannot be
    /// consumed twice on Cosmos (the chain-agnostic nullifier set, mirroring the CKB-side burn_nullifier_registry
    /// with a per-leg domain tag). Fails if the proof is invalid or the event was already recorded.
    RecordCkbEvent {
        window_root: String, seal: String, amount: Uint128, recipient: String, tip_height: u64, k: u64,
        proof: Proof, vk: Vk,
    },
    /// Verify a Groth16 proof against raw public inputs as a TX (not a query), so the heavy pairing runs under a
    /// payable gas budget rather than the low smart-query gas cap. The tx SUCCEEDS iff the proof verifies, so a
    /// confirmed tx is itself the on-chain proof verification. Used for the in-wasm-pairing build on chains
    /// without the BLS host functions.
    AssertCkbProof {
        a: String, b: String, c: String,
        alpha: String, beta: String, gamma: String, delta: String,
        ic: Vec<String>, public_inputs: Vec<String>,
    },
    /// RETURN leg (CKB -> Cosmos): verify a proof that chiOSMO was burned on CKB bound to this event
    /// (window_root, seal, amount, recipient[20-byte osmo account], tip_height, K), nullify the burn seal
    /// replay-once, and send `amount` uosmo to the recipient. The mirror of catom_mint on the Cosmos side.
    ReleaseOnCkbBurn {
        window_root: String, seal: String, amount: Uint128, recipient: String, tip_height: u64, k: u64,
        denom: String, proof: Proof, vk: Vk,
    },
    /// FORWARD leg (CKB -> Cosmos): create the χCKB Osmosis token-factory denom (factory/<contract>/SUBDENOM).
    /// One-time; the contract becomes the denom admin so it can mint. SUBDENOM e.g. "uchickb".
    CreateChiCkbDenom { subdenom: String },
    /// FORWARD leg: verify a proof that CKB value was locked, bound to this CKB event (window_root, seal, amount,
    /// recipient[CKB], tip_height, K), nullify the seal replay-once, and MINT `amount` of the χCKB token-factory
    /// denom to `to` (a Cosmos address). The mirror of catom_mint on the Cosmos side: a real wrapped-CKB token,
    /// wallet/explorer-visible as a native bank denom.
    MintChiCkb {
        window_root: String, seal: String, amount: Uint128, recipient: String, tip_height: u64, k: u64,
        subdenom: String, to: String, proof: Proof, vk: Vk,
    },
    /// MECHANISM DEMO of the forward leg with a proof whose raw event-preimage is not on hand (only its reduced
    /// public inputs): verify the proof against raw public_inputs, nullify public_inputs[1] (the seal), and mint
    /// `amount` χCKB to `to`. Unlike MintChiCkb this does NOT bind amount/recipient in-circuit (that is the
    /// event-bound production path), so it is for the live mint demonstration only.
    MintChiCkbRaw {
        public_inputs: Vec<String>, subdenom: String, to: String, amount: Uint128, proof: Proof, vk: Vk,
    },
}

#[cw_serde]
pub struct VerifyResp { pub valid: bool }

/// Per-leg domain tag for the Cosmos-side nullifier set (mirrors the CKB CHIRAL_NULL_TAG separation).
const NF_DOMAIN: &[u8] = b"chiral:cosmos-ckb:nf:";
fn nf_key(seal: &[u8]) -> Vec<u8> { [NF_DOMAIN, seal].concat() }

#[entry_point]
pub fn instantiate(_d: DepsMut, _e: Env, _i: MessageInfo, _m: InstantiateMsg) -> StdResult<Response> {
    Ok(Response::new())
}

#[entry_point]
pub fn execute(deps: DepsMut, env: Env, _info: MessageInfo, msg: ExecuteMsg) -> StdResult<Response> {
    match msg {
        ExecuteMsg::RecordCkbEvent { window_root, seal, amount, recipient, tip_height, k, proof, vk } => {
            let pubs = derive_event_inputs(&window_root, &seal, amount.u128(), &recipient, tip_height, k).map_err(StdError::generic_err)?;
            let valid = verify_scalars(deps.api, &proof.a, &proof.b, &proof.c, &vk.alpha, &vk.beta, &vk.gamma, &vk.delta, &vk.ic, &pubs).map_err(StdError::generic_err)?;
            if !valid { return Err(StdError::generic_err("CKB event proof did not verify")); }
            let seal_bytes = raw(&seal, 32).map_err(StdError::generic_err)?;
            record_nullifier(deps.storage, &seal_bytes)?;
            Ok(Response::new().add_attribute("action", "record_ckb_event").add_attribute("seal", seal.trim_start_matches("0x")))
        }
        ExecuteMsg::AssertCkbProof { a, b, c, alpha, beta, gamma, delta, ic, public_inputs } => {
            let pubs: Vec<Scalar> = public_inputs.iter().map(|h| scalar_canonical(h)).collect::<Result<_, _>>().map_err(StdError::generic_err)?;
            let valid = verify_scalars(deps.api, &a, &b, &c, &alpha, &beta, &gamma, &delta, &ic, &pubs).map_err(StdError::generic_err)?;
            if !valid { return Err(StdError::generic_err("CKB-state proof did not verify")); }
            Ok(Response::new().add_attribute("action", "assert_ckb_proof").add_attribute("verified", "true"))
        }
        ExecuteMsg::ReleaseOnCkbBurn { window_root, seal, amount, recipient, tip_height, k, denom, proof, vk } => {
            // 1) verify the proof is bound to THIS burn event (amount + recipient committed in-circuit).
            let pubs = derive_burn_inputs(&window_root, &seal, amount.u128(), &recipient, tip_height, k).map_err(StdError::generic_err)?;
            let valid = verify_scalars(deps.api, &proof.a, &proof.b, &proof.c, &vk.alpha, &vk.beta, &vk.gamma, &vk.delta, &vk.ic, &pubs).map_err(StdError::generic_err)?;
            if !valid { return Err(StdError::generic_err("CKB burn proof did not verify")); }
            // 2) replay-once on the burn seal (separate keyspace from the forward leg via the seal itself).
            let seal_bytes = raw(&seal, 32).map_err(StdError::generic_err)?;
            record_nullifier(deps.storage, &seal_bytes)?;
            // 3) release: send `amount` of `denom` to the recipient (20-byte account -> this chain's bech32).
            let rc = raw(&recipient, 20).map_err(StdError::generic_err)?;
            let to = deps.api.addr_humanize(&CanonicalAddr::from(rc.as_slice()))?;
            let send = BankMsg::Send { to_address: to.to_string(), amount: vec![Coin { denom, amount }] };
            Ok(Response::new().add_message(send).add_attribute("action", "release_on_ckb_burn").add_attribute("to", to.to_string()).add_attribute("amount", amount))
        }
        ExecuteMsg::CreateChiCkbDenom { subdenom } => {
            // the contract becomes the admin of factory/<contract>/<subdenom>; one-time.
            #[allow(deprecated)]
            let msg = CosmosMsg::Stargate { type_url: "/osmosis.tokenfactory.v1beta1.MsgCreateDenom".into(), value: msg_create_denom(env.contract.address.as_str(), &subdenom) };
            Ok(Response::new().add_message(msg).add_attribute("action", "create_chickb_denom").add_attribute("denom", format!("factory/{}/{}", env.contract.address, subdenom)))
        }
        ExecuteMsg::MintChiCkb { window_root, seal, amount, recipient, tip_height, k, subdenom, to, proof, vk } => {
            // 1) verify the proof is bound to THIS CKB lock event (amount + recipient committed in-circuit).
            let pubs = derive_event_inputs(&window_root, &seal, amount.u128(), &recipient, tip_height, k).map_err(StdError::generic_err)?;
            let valid = verify_scalars(deps.api, &proof.a, &proof.b, &proof.c, &vk.alpha, &vk.beta, &vk.gamma, &vk.delta, &vk.ic, &pubs).map_err(StdError::generic_err)?;
            if !valid { return Err(StdError::generic_err("CKB lock proof did not verify")); }
            // 2) replay-once on the seal.
            let seal_bytes = raw(&seal, 32).map_err(StdError::generic_err)?;
            record_nullifier(deps.storage, &seal_bytes)?;
            // 3) mint `amount` of the χCKB token-factory denom to `to`.
            let denom = format!("factory/{}/{}", env.contract.address, subdenom);
            #[allow(deprecated)]
            let msg = CosmosMsg::Stargate { type_url: "/osmosis.tokenfactory.v1beta1.MsgMint".into(), value: msg_mint(env.contract.address.as_str(), &denom, &amount.to_string(), &to) };
            Ok(Response::new().add_message(msg).add_attribute("action", "mint_chickb").add_attribute("denom", denom).add_attribute("to", to).add_attribute("amount", amount))
        }
        ExecuteMsg::MintChiCkbRaw { public_inputs, subdenom, to, amount, proof, vk } => {
            if public_inputs.len() < 2 { return Err(StdError::generic_err("need >=2 public inputs")); }
            let pubs: Vec<Scalar> = public_inputs.iter().map(|h| scalar_canonical(h)).collect::<Result<_, _>>().map_err(StdError::generic_err)?;
            let valid = verify_scalars(deps.api, &proof.a, &proof.b, &proof.c, &vk.alpha, &vk.beta, &vk.gamma, &vk.delta, &vk.ic, &pubs).map_err(StdError::generic_err)?;
            if !valid { return Err(StdError::generic_err("CKB proof did not verify")); }
            record_nullifier(deps.storage, &pubs[1].to_bytes())?;          // seal = pi[1]
            let denom = format!("factory/{}/{}", env.contract.address, subdenom);
            #[allow(deprecated)]
            let msg = CosmosMsg::Stargate { type_url: "/osmosis.tokenfactory.v1beta1.MsgMint".into(), value: msg_mint(env.contract.address.as_str(), &denom, &amount.to_string(), &to) };
            Ok(Response::new().add_message(msg).add_attribute("action", "mint_chickb_raw").add_attribute("denom", denom).add_attribute("to", to).add_attribute("amount", amount))
        }
    }
}

/// Insert a seal into the replay-once nullifier set; error if it is already present.
fn record_nullifier(storage: &mut dyn cosmwasm_std::Storage, seal: &[u8]) -> StdResult<()> {
    let key = nf_key(seal);
    if storage.get(&key).is_some() {
        return Err(StdError::generic_err("CKB event already recorded (replay)"));
    }
    storage.set(&key, &[1u8]);
    Ok(())
}

// ---- minimal protobuf encoder for the Osmosis tokenfactory messages (sent as CosmosMsg::Any) ----
fn pb_varint(mut v: u64, out: &mut Vec<u8>) { while v > 0x7f { out.push((v as u8 & 0x7f) | 0x80); v >>= 7; } out.push(v as u8); }
fn pb_field_bytes(field: u32, b: &[u8], out: &mut Vec<u8>) { pb_varint(((field as u64) << 3) | 2, out); pb_varint(b.len() as u64, out); out.extend_from_slice(b); }
/// Coin { 1: denom, 2: amount(decimal string) }
fn pb_coin(denom: &str, amount: &str) -> Vec<u8> { let mut o = Vec::new(); pb_field_bytes(1, denom.as_bytes(), &mut o); pb_field_bytes(2, amount.as_bytes(), &mut o); o }
/// MsgCreateDenom { 1: sender, 2: subdenom }
fn msg_create_denom(sender: &str, subdenom: &str) -> Binary {
    let mut o = Vec::new(); pb_field_bytes(1, sender.as_bytes(), &mut o); pb_field_bytes(2, subdenom.as_bytes(), &mut o); Binary::new(o)
}
/// MsgMint { 1: sender, 2: amount(Coin), 3: mintToAddress }
fn msg_mint(sender: &str, denom: &str, amount: &str, to: &str) -> Binary {
    let mut o = Vec::new();
    pb_field_bytes(1, sender.as_bytes(), &mut o);
    pb_field_bytes(2, &pb_coin(denom, amount), &mut o);
    pb_field_bytes(3, to.as_bytes(), &mut o);
    Binary::new(o)
}

#[entry_point]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::VerifyCkbProof { a, b, c, alpha, beta, gamma, delta, ic, public_inputs } => {
            let pubs: Vec<Scalar> = public_inputs.iter().map(|h| scalar_canonical(h)).collect::<Result<_, _>>().map_err(StdError::generic_err)?;
            let valid = verify_scalars(deps.api, &a, &b, &c, &alpha, &beta, &gamma, &delta, &ic, &pubs).map_err(StdError::generic_err)?;
            to_json_binary(&VerifyResp { valid })
        }
        QueryMsg::VerifyCkbEvent { window_root, seal, amount, recipient, tip_height, k, proof, vk } => {
            let pubs = derive_event_inputs(&window_root, &seal, amount.u128(), &recipient, tip_height, k).map_err(StdError::generic_err)?;
            let valid = verify_scalars(deps.api, &proof.a, &proof.b, &proof.c, &vk.alpha, &vk.beta, &vk.gamma, &vk.delta, &vk.ic, &pubs).map_err(StdError::generic_err)?;
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
/// A raw public input given as a canonical (already reduced, < r) 32-byte little-endian scalar.
fn scalar_canonical(h: &str) -> Result<Scalar, String> {
    let arr: [u8; 32] = hex::decode(h.trim_start_matches("0x")).map_err(|_| "scalar hex")?.try_into().map_err(|_| "scalar len")?;
    Option::from(Scalar::from_bytes(&arr)).ok_or_else(|| "scalar not canonical".to_string()) // little-endian
}

/// LEmod: interpret up to 64 little-endian bytes as an integer and reduce mod the scalar order r. This matches
/// arkworks' `Fr::from_le_bytes_mod_order` used by the circuit (32-byte hashes can exceed r, so they must be
/// reduced, not parsed canonically). Implemented via the wide (512-bit) reduction.
fn le_mod_scalar(bytes: &[u8]) -> Result<Scalar, String> {
    if bytes.len() > 64 { return Err("le_mod too long".into()); }
    let mut wide = [0u8; 64];
    wide[..bytes.len()].copy_from_slice(bytes);
    Ok(Scalar::from_bytes_wide(&wide))
}

/// Standard unkeyed BLAKE2b with a 32-byte digest (matches the circuit's b2b()).
fn blake2b256(d: &[u8]) -> [u8; 32] {
    let mut h = Blake2bVar::new(32).expect("32 is a valid blake2b output size");
    h.update(d);
    let mut o = [0u8; 32];
    h.finalize_variable(&mut o).expect("32-byte output");
    o
}

/// Derive the leap circuit's 5 public inputs from a concrete CKB event. window_root/seal are 32-byte hex,
/// recipient 28-byte hex, amount a u128 (encoded 16-byte little-endian, as the receipt body carries it).
pub fn derive_event_inputs(window_root: &str, seal: &str, amount: u128, recipient: &str, tip_height: u64, k: u64) -> Result<[Scalar; 5], String> {
    let wr = raw(window_root, 32)?;
    let sl = raw(seal, 32)?;
    let rc = raw(recipient, 28)?;
    // commitment = blake2b256( amount(16 LE) ‖ recipient(28) ‖ seal(32) )
    let mut pre = Vec::with_capacity(16 + 28 + 32);
    pre.extend_from_slice(&amount.to_le_bytes());
    pre.extend_from_slice(&rc);
    pre.extend_from_slice(&sl);
    let comm = blake2b256(&pre);
    Ok([
        le_mod_scalar(&wr)?,
        le_mod_scalar(&sl)?,
        le_mod_scalar(&comm)?,
        Scalar::from(tip_height),
        Scalar::from(k),
    ])
}

/// Derive the RETURN-leg (CKB->Cosmos) burn proof's 5 public inputs from the burn event. Same shape as the
/// forward derivation but the recipient is the 20-byte Osmosis account address (what xosmo_burn_receipt commits):
/// commitment = blake2b256( amount(16 LE) ‖ cosmos_recipient(20) ‖ seal(32) ).
pub fn derive_burn_inputs(window_root: &str, seal: &str, amount: u128, recipient: &str, tip_height: u64, k: u64) -> Result<[Scalar; 5], String> {
    let wr = raw(window_root, 32)?;
    let sl = raw(seal, 32)?;
    let rc = raw(recipient, 20)?;
    let mut pre = Vec::with_capacity(16 + 20 + 32);
    pre.extend_from_slice(&amount.to_le_bytes());
    pre.extend_from_slice(&rc);
    pre.extend_from_slice(&sl);
    let comm = blake2b256(&pre);
    Ok([le_mod_scalar(&wr)?, le_mod_scalar(&sl)?, le_mod_scalar(&comm)?, Scalar::from(tip_height), Scalar::from(k)])
}

/// vk_x = ic[0] + sum(pub_i * ic[i+1]), returned compressed (48 bytes). The only EC arithmetic done in wasm
/// for the host-function path.
#[cfg(not(feature = "inwasm"))]
fn compute_vk_x(ic: &[String], pubs: &[Scalar]) -> Result<[u8; 48], String> {
    if ic.len() != pubs.len() + 1 { return Err("ic/pubs length".into()); }
    let mut acc = G1Projective::from(g1(&ic[0])?);
    for i in 0..pubs.len() {
        acc += G1Projective::from(g1(&ic[i + 1])?) * pubs[i];
    }
    Ok(G1Affine::from(acc).to_compressed())
}

/// Groth16 over BLS12-381, final pairing via the host function:
/// e(alpha,beta) * e(vk_x,gamma) * e(C,delta) == e(A,B).
/// ps (G1, 48B each) = alpha || vk_x || C ; qs (G2, 96B each) = beta || gamma || delta ; r = A ; s = B.
#[cfg(not(feature = "inwasm"))]
pub fn verify_scalars(api: &dyn Api, a: &str, b: &str, c: &str, alpha: &str, beta: &str, gamma: &str, delta: &str, ic: &[String], pubs: &[Scalar]) -> Result<bool, String> {
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

/// In-wasm pairing fallback for chains whose wasmvm lacks the BLS12-381 host functions (e.g. osmo-test-5): the
/// whole Groth16 check runs in wasm via the bls12_381 crate's Miller loop (`inwasm` feature pulls in `pairings`).
/// Same math, larger/slower, but self-contained, no host call. Identical equation to the host-fn path.
#[cfg(feature = "inwasm")]
fn g2(h: &str) -> Result<bls12_381::G2Affine, String> {
    let arr: [u8; 96] = raw(h, 96)?.try_into().map_err(|_| "g2 len")?;
    Option::from(bls12_381::G2Affine::from_compressed(&arr)).ok_or_else(|| "g2 point".to_string())
}
#[cfg(feature = "inwasm")]
pub fn verify_scalars(_api: &dyn Api, a: &str, b: &str, c: &str, alpha: &str, beta: &str, gamma: &str, delta: &str, ic: &[String], pubs: &[Scalar]) -> Result<bool, String> {
    use bls12_381::{multi_miller_loop, G2Prepared, Gt};
    if ic.len() != pubs.len() + 1 { return Err("ic/pubs length".into()); }
    let a = g1(a)?; let b = g2(b)?; let c = g1(c)?;
    let alpha = g1(alpha)?; let beta = g2(beta)?; let gamma = g2(gamma)?; let delta = g2(delta)?;
    let mut vk_x = G1Projective::from(g1(&ic[0])?);
    for i in 0..pubs.len() { vk_x += G1Projective::from(g1(&ic[i + 1])?) * pubs[i]; }
    let vk_x = G1Affine::from(vk_x);
    let ml = multi_miller_loop(&[
        (&a, &G2Prepared::from(b)),
        (&(-vk_x), &G2Prepared::from(gamma)),
        (&(-c), &G2Prepared::from(delta)),
        (&(-alpha), &G2Prepared::from(beta)),
    ]);
    Ok(ml.final_exponentiation() == Gt::identity())
}

/// Convenience wrapper for raw-scalar public inputs given as 32-byte LE hex.
pub fn verify(api: &dyn Api, a: &str, b: &str, c: &str, alpha: &str, beta: &str, gamma: &str, delta: &str, ic: &[String], pubs: &[String]) -> Result<bool, String> {
    let pubs: Vec<Scalar> = pubs.iter().map(|h| scalar_canonical(h)).collect::<Result<_, _>>()?;
    verify_scalars(api, a, b, c, alpha, beta, gamma, delta, ic, &pubs)
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
        for i in 0..pubs.len() { vk_x += G1Projective::from(g1(&ic[i + 1])?) * scalar_canonical(&pubs[i])?; }
        let vk_x = G1Affine::from(vk_x);
        let ml = multi_miller_loop(&[
            (&a, &G2Prepared::from(b)),
            (&(-vk_x), &G2Prepared::from(gamma)),
            (&(-c), &G2Prepared::from(delta)),
            (&(-alpha), &G2Prepared::from(beta)),
        ]);
        Ok(ml.final_exponentiation() == Gt::identity())
    }

    struct Inputs { a: String, b: String, c: String, alpha: String, beta: String, gamma: String, delta: String, ic: Vec<String>, pubs: Vec<String>, pubs_dec: Vec<String> }
    fn load() -> Inputs {
        let j: serde_json::Value = serde_json::from_str(include_str!("../../../ckb-to-cardano/circuit/ceremony/leap_bound_windowed_redeemer.json")).unwrap();
        let s = |v: &serde_json::Value| v.as_str().unwrap().to_string();
        let proof = &j["proof"]; let vk = &j["vk"];
        let ic: Vec<String> = vk["ic"].as_array().unwrap().iter().map(s).collect();
        let pubs_dec: Vec<String> = j["public_inputs_dec"].as_array().unwrap().iter().map(s).collect();
        // public inputs: decimal -> 32-byte little-endian hex
        let pubs: Vec<String> = pubs_dec.iter().map(|v| {
            let n = BigUint::parse_bytes(v.as_bytes(), 10).unwrap();
            let mut le = n.to_bytes_le(); le.resize(32, 0);
            hex::encode(le)
        }).collect();
        Inputs { a: s(&proof["a"]), b: s(&proof["b"]), c: s(&proof["c"]),
            alpha: s(&vk["alpha_g1"]), beta: s(&vk["beta_g2"]), gamma: s(&vk["gamma_g2"]), delta: s(&vk["delta_g2"]), ic, pubs, pubs_dec }
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

    /// The event -> public-inputs derivation is byte-exact with the leap circuit, cross-checked against the
    /// independent off-chain reference (derive_inputs.mjs: @noble/curves + @noble/hashes/blake2). The vectors
    /// below are that reference's output for the constructed event in derive_inputs.mjs.
    #[test]
    fn binds_event_to_public_inputs() {
        // constructed event (identical to derive_inputs.mjs)
        let window_root = "ff".repeat(32);
        let seal: String = (0u8..32).map(|i| format!("{:02x}", i)).collect();
        let recipient = "aa".repeat(28);
        let amount: u128 = 123456789;
        let tip_height: u64 = 21388353;
        let k: u64 = 12;

        let pubs = derive_event_inputs(&window_root, &seal, amount, &recipient, tip_height, k).unwrap();

        // reference: canonical 32-byte little-endian hex of each derived field element (from derive_inputs.mjs)
        let expected = [
            "fdffffff0100000002480300fab78458f54fbcecef4f8c996f05c5ac59b12418", // window_root (0xff*32 reduced mod r)
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", // seal
            "08289493b84761ae123ffb57c21d6e6bd274b87749fe97fcea7533b071caa132", // commitment = blake2b256(amount||recip||seal)
            "415c460100000000000000000000000000000000000000000000000000000000", // tip_height = 21388353
            "0c00000000000000000000000000000000000000000000000000000000000000", // k = 12
        ];
        for (i, exp) in expected.iter().enumerate() {
            assert_eq!(hex::encode(pubs[i].to_bytes()), *exp, "derived public input {i} differs from the off-chain reference");
        }
    }

    /// The RETURN-leg burn derivation (20-byte recipient), cross-checked against derive_inputs.mjs's burn vectors.
    #[test]
    fn binds_burn_event_to_public_inputs() {
        let window_root = "ee".repeat(32);
        let seal: String = (0u8..32).map(|i| format!("{:02x}", i.wrapping_add(1))).collect();
        let recipient = "bb".repeat(20);
        let pubs = derive_burn_inputs(&window_root, &seal, 7654321, &recipient, 20000000, 7).unwrap();
        let expected = [
            "eceeeeeef0eeeeeef036f2eee8a67347e43eabdbde3e7b885ef4b39b48a01307", // window_root (0xee*32 reduced)
            "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20", // seal
            "4cff559d7f8462c9df3b7e9a43c9908e190aff5531de52d9aaee88db0729385c", // commitment = blake2b(amount||recip20||seal)
            "002d310100000000000000000000000000000000000000000000000000000000", // tip_height = 20000000
            "0700000000000000000000000000000000000000000000000000000000000000", // k = 7
        ];
        for (i, exp) in expected.iter().enumerate() {
            assert_eq!(hex::encode(pubs[i].to_bytes()), *exp, "burn public input {i} differs from the off-chain reference");
        }
    }

    /// Forward leg: MintChiCkb is fail-closed (a proof not matching the claimed lock event is rejected, no mint),
    /// and the tokenfactory MsgMint is well-formed (protobuf: sender, Coin{denom,amount}, mintToAddress).
    #[test]
    fn mint_chickb_fail_closed_and_msg_shape() {
        use cosmwasm_std::testing::mock_env;
        use cosmwasm_std::{Addr, CosmosMsg, MessageInfo, Uint128};
        let mut deps = mock_dependencies();
        let i = load();
        let vk = Vk { alpha: i.alpha.clone(), beta: i.beta.clone(), gamma: i.gamma.clone(), delta: i.delta.clone(), ic: i.ic.clone() };
        let proof = Proof { a: i.a.clone(), b: i.b.clone(), c: i.c.clone() };
        let info = MessageInfo { sender: Addr::unchecked("anyone"), funds: vec![] };
        // mismatched event vs proof -> rejected, nothing minted.
        let msg = ExecuteMsg::MintChiCkb {
            window_root: "ff".repeat(32), seal: (0u8..32).map(|x| format!("{:02x}", x)).collect(),
            amount: Uint128::new(123456789), recipient: "aa".repeat(28), tip_height: 21388353, k: 12,
            subdenom: "uchickb".into(), to: "osmo1recipient".into(), proof, vk,
        };
        assert!(execute(deps.as_mut(), mock_env(), info, msg).is_err(), "a mint with a non-matching proof must be rejected");

        // the MsgMint protobuf is well-formed and decodes to the expected fields (independent decoder).
        fn pb_first<'a>(b: &'a [u8], field: u32) -> Option<&'a [u8]> {
            let mut i = 0usize;
            while i < b.len() {
                let (mut key, mut sh) = (0u64, 0u32);
                loop { let by = b[i]; i += 1; key |= ((by & 0x7f) as u64) << sh; if by & 0x80 == 0 { break; } sh += 7; }
                let f = (key >> 3) as u32; let wire = key & 7;
                if wire == 2 {
                    let (mut len, mut s2) = (0u64, 0u32);
                    loop { let by = b[i]; i += 1; len |= ((by & 0x7f) as u64) << s2; if by & 0x80 == 0 { break; } s2 += 7; }
                    let len = len as usize;
                    if f == field { return Some(&b[i..i + len]); }
                    i += len;
                } else { return None; }
            }
            None
        }
        let m = msg_mint("osmo1contract", "factory/osmo1contract/uchickb", "777", "osmo1to");
        let b = m.as_slice();
        assert_eq!(pb_first(b, 1).unwrap(), b"osmo1contract");                       // sender
        let coin = pb_first(b, 2).unwrap();
        assert_eq!(pb_first(coin, 1).unwrap(), b"factory/osmo1contract/uchickb");     // Coin.denom
        assert_eq!(pb_first(coin, 2).unwrap(), b"777");                               // Coin.amount
        assert_eq!(pb_first(b, 3).unwrap(), b"osmo1to");                              // mintToAddress
    }

    /// ReleaseOnCkbBurn is fail-closed: a proof that does not match the claimed burn event is rejected, and
    /// nothing is released or nullified. (The success path needs a real CKB-burn proof, which requires the
    /// CKB-state proving pipeline; that is the documented residual for the live release.)
    #[test]
    fn release_on_ckb_burn_fail_closed() {
        use cosmwasm_std::testing::mock_env;
        use cosmwasm_std::{Addr, MessageInfo, Uint128};
        let mut deps = mock_dependencies();
        let i = load();
        let vk = Vk { alpha: i.alpha.clone(), beta: i.beta.clone(), gamma: i.gamma.clone(), delta: i.delta.clone(), ic: i.ic.clone() };
        let proof = Proof { a: i.a.clone(), b: i.b.clone(), c: i.c.clone() };
        let info = MessageInfo { sender: Addr::unchecked("anyone"), funds: vec![] };
        let msg = ExecuteMsg::ReleaseOnCkbBurn {
            window_root: "ee".repeat(32), seal: (0u8..32).map(|i| format!("{:02x}", i.wrapping_add(1))).collect(),
            amount: Uint128::new(7654321), recipient: "bb".repeat(20), tip_height: 20000000, k: 7,
            denom: "uosmo".into(), proof, vk,
        };
        let res = execute(deps.as_mut(), mock_env(), info, msg);
        // rejected before the nullifier insert or the bank send, so nothing is released.
        assert!(res.is_err(), "a burn proof not matching the event must be rejected");
    }

    /// Tie the integer-valued public inputs (tip_height, K) to the REAL committed redeemer: the contract's
    /// u64 -> scalar binding must reproduce the real proof's pi[3] and pi[4] exactly. (The hash-valued inputs
    /// window_root/seal/commitment cannot be tied here because the redeemer carries only their reduced scalars,
    /// not the raw preimage; the prover now emits that preimage as a sidecar to close the round-trip.)
    /// The Cosmos-side replay-once registry: a verified CKB event records its seal, and the same event cannot be
    /// recorded twice. Also checks execute() is fail-closed (a proof that does not match the claimed event is
    /// rejected before anything is stored).
    #[test]
    fn records_and_blocks_replay() {
        use cosmwasm_std::testing::mock_env;
        use cosmwasm_std::{Addr, MessageInfo, Uint128};
        let mut deps = mock_dependencies();
        let i = load();

        // execute() is fail-closed: the constructed event does not match the real proof's committed event, so the
        // derived inputs verify to false and nothing is recorded.
        let vk = Vk { alpha: i.alpha.clone(), beta: i.beta.clone(), gamma: i.gamma.clone(), delta: i.delta.clone(), ic: i.ic.clone() };
        let proof = Proof { a: i.a.clone(), b: i.b.clone(), c: i.c.clone() };
        let info = MessageInfo { sender: Addr::unchecked("anyone"), funds: vec![] };
        let msg = ExecuteMsg::RecordCkbEvent {
            window_root: "ff".repeat(32), seal: (0u8..32).map(|x| format!("{:02x}", x)).collect(),
            amount: Uint128::new(123456789), recipient: "aa".repeat(28), tip_height: 21388353, k: 12, proof, vk,
        };
        assert!(execute(deps.as_mut(), mock_env(), info, msg).is_err(), "mismatched event/proof must be rejected");

        // replay-once registry against the REAL verifying proof: record the seal once, reject the second time.
        let pubs: Vec<Scalar> = i.pubs.iter().map(|h| scalar_canonical(h).unwrap()).collect();
        let valid = verify_scalars(&deps.api, &i.a, &i.b, &i.c, &i.alpha, &i.beta, &i.gamma, &i.delta, &i.ic, &pubs).unwrap();
        assert!(valid, "the real proof must verify before recording");
        let nf = pubs[1].to_bytes(); // seal scalar = the unique CKB event id
        record_nullifier(&mut deps.storage, &nf).expect("first record ok");
        assert!(record_nullifier(&mut deps.storage, &nf).is_err(), "second record of the same seal must be rejected");
        // a different seal still records
        let other = pubs[0].to_bytes();
        record_nullifier(&mut deps.storage, &other).expect("a distinct seal records ok");
    }

    #[test]
    fn integer_inputs_match_real_redeemer() {
        let i = load();
        assert_eq!(i.pubs_dec[3], "21388353", "redeemer pi[3] is the tip height");
        assert_eq!(i.pubs_dec[4], "12", "redeemer pi[4] is K");
        let dec_to_scalar = |d: &str| {
            let n = BigUint::parse_bytes(d.as_bytes(), 10).unwrap();
            let mut le = n.to_bytes_le(); le.resize(32, 0);
            scalar_canonical(&hex::encode(le)).unwrap()
        };
        assert_eq!(Scalar::from(21388353u64), dec_to_scalar(&i.pubs_dec[3]), "tip_height binding != real redeemer pi[3]");
        assert_eq!(Scalar::from(12u64), dec_to_scalar(&i.pubs_dec[4]), "K binding != real redeemer pi[4]");
    }
}
