//! Host-side verification of the SEC A3 canonical Conway-output decoder used in bound_asset_unified.rs.
//! The four functions below are byte-for-byte the production decoder (no ckb-std deps); this binary builds
//! synthetic Conway tx bodies and asserts seal_at_lock returns the right Some(true)/Some(false)/None, so the
//! GENESIS (needs Some(true)) and FINALIZE (needs Some(false)) call sites fail closed on any ambiguity.

const A3_MAX_DEPTH: usize = 64;
fn ohdr(b:&[u8], i:usize) -> Option<(u8,u64,usize)> {
    let ib = *b.get(i)?; let m = ib>>5; let lo = ib&0x1f;
    match lo {
        0..=23 => Some((m, lo as u64, i+1)),
        24 => { if i+1>=b.len(){return None;} Some((m, b[i+1] as u64, i+2)) }
        25 => { if i+2>=b.len(){return None;} Some((m, u16::from_be_bytes([b[i+1],b[i+2]]) as u64, i+3)) }
        26 => { if i+4>=b.len(){return None;} Some((m, u32::from_be_bytes([b[i+1],b[i+2],b[i+3],b[i+4]]) as u64, i+5)) }
        27 => { if i+8>=b.len(){return None;} Some((m, u64::from_be_bytes([b[i+1],b[i+2],b[i+3],b[i+4],b[i+5],b[i+6],b[i+7],b[i+8]]), i+9)) }
        _ => None,
    }
}
fn oskip(b:&[u8], i:usize, depth:usize) -> Option<usize> {
    if depth > A3_MAX_DEPTH { return None; }
    let (m,a,j)=ohdr(b,i)?;
    match m {
        0|1|7 => Some(j),
        2|3 => { let e=j.checked_add(a as usize)?; if e>b.len(){None}else{Some(e)} }
        4 => { let mut k=j; for _ in 0..a { k=oskip(b,k,depth+1)?; } Some(k) }
        5 => { let mut k=j; for _ in 0..a { k=oskip(b,k,depth+1)?; k=oskip(b,k,depth+1)?; } Some(k) }
        6 => oskip(b,j,depth+1),
        _ => None,
    }
}
fn val_has_policy(b:&[u8], va:usize, seal_policy:&[u8]) -> Option<bool> {
    let (vm,vlen,vj)=ohdr(b,va)?;
    if vm==0 { return Some(false); }
    if vm!=4 || vlen<2 { return None; }
    let ca = oskip(b,vj,0)?;
    let (mm,mc,mut p)=ohdr(b,ca)?;
    if mm!=5 { return None; }
    for _ in 0..mc {
        let (pm,pl,pa)=ohdr(b,p)?;
        if pm!=2 { return None; }
        let pend = pa.checked_add(pl as usize)?; if pend>b.len() { return None; }
        let is_seal = pl as usize==seal_policy.len() && &b[pa..pend]==seal_policy;
        let after = oskip(b,pend,0)?;
        if is_seal { return Some(true); }
        p = after;
    }
    Some(false)
}
fn seal_at_lock(b:&[u8], lock_addr:&[u8], seal_policy:&[u8]) -> Option<bool> {
    let (m,n,mut i)=ohdr(b,0)?;
    if m!=5 { return None; }
    for _ in 0..n {
        let (km,key,ki)=ohdr(b,i)?;
        if km!=0 { return None; }
        if key==1 {
            let (om,oc,oj)=ohdr(b,ki)?;
            if om!=4 { return None; }
            let mut j=oj; let mut found=false;
            for _ in 0..oc {
                let (otm,oarg,oi2)=ohdr(b,j)?;
                let (addr_lo,addr_hi,val_at,next);
                if otm==5 {
                    let mut k=oi2; let (mut a0,mut a1,mut v)=(0usize,0usize,0usize);
                    for _ in 0..oarg {
                        let (_em,ek,eki)=ohdr(b,k)?;
                        if ek==0 { let (am,al,aa)=ohdr(b,eki)?; if am!=2 {return None;}
                            let e=aa.checked_add(al as usize)?; if e>b.len(){return None;} a0=aa; a1=e; k=e; }
                        else if ek==1 { v=eki; k=oskip(b,eki,0)?; }
                        else { k=oskip(b,eki,0)?; }
                    }
                    addr_lo=a0; addr_hi=a1; val_at=v; next=k;
                } else if otm==4 {
                    if oarg<2 { return None; }
                    let (am,al,aa)=ohdr(b,oi2)?; if am!=2 {return None;}
                    let e=aa.checked_add(al as usize)?; if e>b.len(){return None;}
                    addr_lo=aa; addr_hi=e; val_at=e; next=oskip(b,j,0)?;
                } else { return None; }
                if addr_hi>addr_lo && addr_hi<=b.len() && &b[addr_lo..addr_hi]==lock_addr && val_at!=0 {
                    if val_has_policy(b,val_at,seal_policy)? { found=true; }
                }
                j=next;
            }
            return Some(found);
        } else { i=oskip(b,ki,0)?; }
    }
    None
}

// ---- tiny CBOR builders ----
fn uint(v: u64) -> Vec<u8> {
    if v < 24 { vec![v as u8] }
    else if v < 256 { vec![0x18, v as u8] }
    else if v < 65536 { let mut o=vec![0x19]; o.extend_from_slice(&(v as u16).to_be_bytes()); o }
    else { let mut o=vec![0x1a]; o.extend_from_slice(&(v as u32).to_be_bytes()); o }
}
fn bytes(b: &[u8]) -> Vec<u8> {
    let mut o = Vec::new();
    let l = b.len();
    if l < 24 { o.push(0x40 + l as u8); } else { o.push(0x58); o.push(l as u8); }
    o.extend_from_slice(b); o
}
fn map_hdr(n: u64) -> Vec<u8> { vec![0xa0 + n as u8] }
fn arr_hdr(n: u64) -> Vec<u8> { vec![0x80 + n as u8] }

const SEAL: [u8;28] = [0xaa;28];
const NAME: [u8;4] = [0x53,0x45,0x41,0x4c];
const LOCK: [u8;28] = [0xbb;28];
const OTHER_ADDR: [u8;28] = [0xcc;28];

/// multiasset value [coin, { policy: { name: amt } }]
fn value_with(policy: &[u8]) -> Vec<u8> {
    let mut ma = map_hdr(1);                    // 1 policy
    ma.extend(bytes(policy));
    let mut inner = map_hdr(1);                 // 1 asset
    inner.extend(bytes(&NAME));
    inner.extend(uint(1));
    ma.extend(inner);
    let mut v = arr_hdr(2);                     // [coin, multiasset]
    v.extend(uint(2_000_000));
    v.extend(ma);
    v
}
fn map_output(addr: &[u8], value: Vec<u8>) -> Vec<u8> {
    let mut o = map_hdr(2);                     // {0: addr, 1: value}
    o.extend(uint(0)); o.extend(bytes(addr));
    o.extend(uint(1)); o.extend(value);
    o
}
fn array_output(addr: &[u8], value: Vec<u8>) -> Vec<u8> {
    let mut o = arr_hdr(2);                     // [addr, value]
    o.extend(bytes(addr));
    o.extend(value);
    o
}
/// a tx body map { 0: inputs(empty set), 1: outputs(array) }
fn txbody(outputs: Vec<Vec<u8>>) -> Vec<u8> {
    let mut b = map_hdr(2);
    b.extend(uint(0)); b.extend(arr_hdr(0));   // 0: [] inputs
    b.extend(uint(1));
    b.extend(arr_hdr(outputs.len() as u64));
    for o in outputs { b.extend(o); }
    b
}

fn main() {
    // 1) seal recreated at lock (map output) -> Some(true)
    let t1 = txbody(vec![ map_output(&LOCK, value_with(&SEAL)) ]);
    assert_eq!(seal_at_lock(&t1, &LOCK, &SEAL), Some(true), "map output seal@lock");

    // 2) seal at a DIFFERENT address -> Some(false)
    let t2 = txbody(vec![ map_output(&OTHER_ADDR, value_with(&SEAL)) ]);
    assert_eq!(seal_at_lock(&t2, &LOCK, &SEAL), Some(false), "seal at other addr");

    // 3) output at lock but value is a bare coin (no assets) -> Some(false)
    let t3 = txbody(vec![ map_output(&LOCK, uint(2_000_000)) ]);
    assert_eq!(seal_at_lock(&t3, &LOCK, &SEAL), Some(false), "coin-only at lock");

    // 4) legacy ARRAY output carrying the seal at lock -> Some(true) (evasion via output form is caught)
    let t4 = txbody(vec![ array_output(&LOCK, value_with(&SEAL)) ]);
    assert_eq!(seal_at_lock(&t4, &LOCK, &SEAL), Some(true), "array output seal@lock");

    // 5) seal present at lock but among MANY outputs (one decoy first) -> Some(true)
    let t5 = txbody(vec![ map_output(&OTHER_ADDR, uint(5)), map_output(&LOCK, value_with(&SEAL)) ]);
    assert_eq!(seal_at_lock(&t5, &LOCK, &SEAL), Some(true), "seal among outputs");

    // 6) truncated body -> None (fails CLOSED for both genesis and finalize)
    let mut t6 = t1.clone(); t6.truncate(t6.len()-3);
    assert_eq!(seal_at_lock(&t6, &LOCK, &SEAL), None, "truncated -> None");

    // 7) indefinite-length output array (0x9f...) -> None (cannot be silently mis-parsed)
    let mut t7 = map_hdr(2);
    t7.extend(uint(0)); t7.extend(arr_hdr(0));
    t7.extend(uint(1)); t7.push(0x9f); // indefinite-length array
    t7.extend(map_output(&LOCK, value_with(&SEAL))); t7.push(0xff);
    assert_eq!(seal_at_lock(&t7, &LOCK, &SEAL), None, "indefinite array -> None");

    // 8) a different policy at lock (not the seal) -> Some(false)
    let t8 = txbody(vec![ map_output(&LOCK, value_with(&[0xee;28])) ]);
    assert_eq!(seal_at_lock(&t8, &LOCK, &SEAL), Some(false), "other policy at lock");

    println!("A3 decoder: all 8 cases pass");
}
