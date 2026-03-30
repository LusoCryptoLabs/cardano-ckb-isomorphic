use mithril_stm::{AggregateSignature, AggregateVerificationKey, Parameters, MithrilMembershipDigest};
type D = MithrilMembershipDigest;

fn main() {
    let j: serde_json::Value = serde_json::from_reader(std::fs::File::open("mithril.json").unwrap()).unwrap();
    let ms_s = j["ms"].as_str().unwrap();
    let avk_s = j["avk"].as_str().unwrap();
    let sm = j["sm"].as_str().unwrap().to_string();

    let avk: AggregateVerificationKey<D> = serde_json::from_str(avk_s).expect("avk deser");
    let sig: AggregateSignature<D> = serde_json::from_str(ms_s).expect("sig deser");
    let params = Parameters { k: 1944, m: 16948, phi_f: 0.2 };

    let raw32: Vec<u8> = (0..32).map(|i| u8::from_str_radix(&sm[i*2..i*2+2],16).unwrap()).collect();
    for (name, msg) in [("raw32", raw32.clone()), ("ascii_hex64", sm.clone().into_bytes())] {
        match sig.verify(&msg, &avk, &params) {
            Ok(())  => println!("VERIFIED  msg={}", name),
            Err(e)  => println!("fail      msg={}  err={:?}", name, e),
        }
    }
}
