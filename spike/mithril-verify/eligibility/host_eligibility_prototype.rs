use blake2::{Blake2b512, Digest};
use num_bigint::{BigInt, Sign};
use num_rational::Ratio;
use num_traits::{One, Signed};

fn taylor_comparison(bound: usize, cmp: Ratio<BigInt>, x: Ratio<BigInt>) -> bool {
    let mut new_x = x.clone();
    let mut phi: Ratio<BigInt> = One::one();
    let mut divisor: BigInt = One::one();
    for _ in 0..bound {
        phi += new_x.clone();
        divisor += 1;
        new_x = (new_x.clone() * x.clone()) / divisor.clone();
        let error_term = new_x.clone().abs() * BigInt::from(3);
        if cmp > (phi.clone() + error_term.clone()) { return false; }
        else if cmp < phi.clone() - error_term.clone() { return true; }
    }
    false
}
fn is_lottery_won(phi_f: f64, ev: [u8;64], stake: u64, total_stake: u64) -> bool {
    if (phi_f - 1.0).abs() < f64::EPSILON { return true; }
    let ev_max = BigInt::from(2u8).pow(512);
    let ev = BigInt::from_bytes_le(Sign::Plus, &ev);
    let q = Ratio::new_raw(ev_max.clone(), &ev_max - ev);
    let c = Ratio::from_float((1.0 - phi_f).ln()).unwrap();
    let w = Ratio::new_raw(BigInt::from(stake), BigInt::from(total_stake));
    let x = -(w * c);
    taylor_comparison(1000, q, x)
}
fn ev(msgp:&[u8], index:u64, sigma:&[u8]) -> [u8;64] {
    let h = Blake2b512::new().chain_update(b"map").chain_update(msgp)
        .chain_update(index.to_le_bytes()).chain_update(sigma).finalize();
    let mut o=[0u8;64]; o.copy_from_slice(&h); o
}
fn main() {
    let j: serde_json::Value = serde_json::from_reader(std::fs::File::open("elig.json").unwrap()).unwrap();
    let msgp = hex::decode(j["msgp"].as_str().unwrap()).unwrap();
    let total: u64 = j["total_stake"].as_u64().unwrap();
    let phi_f = 0.2f64;
    let mut won=0u64; let mut lost=0u64;
    for s in j["sigs"].as_array().unwrap() {
        let sigma = hex::decode(s["sigma"].as_str().unwrap()).unwrap();
        let stake = s["stake"].as_u64().unwrap();
        for idx in s["indexes"].as_array().unwrap() {
            let i = idx.as_u64().unwrap();
            let e = ev(&msgp, i, &sigma);
            if is_lottery_won(phi_f, e, stake, total) { won+=1 } else { lost+=1 }
        }
    }
    println!("eligibility: won={won} lost={lost}  (lost MUST be 0 for a valid cert)");
}
