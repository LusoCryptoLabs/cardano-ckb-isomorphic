//! checkpoint_consensus_q - the FULL production gate: the checkpoint advances only when a proof that is BOTH
//! quantum-secure (cumulative-difficulty STARK with its composition FRI-tested over F_p⁴ + grinding + 100
//! queries) AND attests the real difficulty transition (proof.total_old→total_new == in_total→out_total),
//! bound to this exact checkpoint, is present. The composition of every mechanism in this spike.
//! Exit: 0 accept; 20 proof invalid; 21 epoch; 22 not heavier; 23 totals mismatch; 1/2/3/5 malformed.
#![no_std]
#![no_main]
use ckb_std::ckb_constants::Source;
use ckb_std::error::SysError;
use ckb_std::high_level::{load_cell_data, load_witness};
use fri_core::consensus::{de_cum_q, verify_cum_q_seeded};
ckb_std::entry!(program_entry);
ckb_std::default_alloc!({ 16 * 1024 }, { 2560 * 1024 }, 64);

const GENESIS: [u8; 48] = [0u8; 48];

fn read48(src: Source) -> Result<Option<[u8; 48]>, i8> {
    match load_cell_data(0, src) {
        Ok(d) if d.len() == 48 => { let mut o = [0u8; 48]; o.copy_from_slice(&d); Ok(Some(o)) }
        Ok(_) => Err(5),
        Err(SysError::IndexOutOfBound) => Ok(None),
        Err(_) => Err(2),
    }
}
fn u64le(b: &[u8]) -> u64 { let mut x = [0u8; 8]; x.copy_from_slice(b); u64::from_le_bytes(x) }

fn program_entry() -> i8 {
    let out = match read48(Source::GroupOutput) { Ok(Some(o)) => o, Ok(None) => return 1, Err(e) => return e };
    let inp = match read48(Source::GroupInput) { Ok(v) => v, Err(e) => return e };
    match inp {
        None => if out == GENESIS { 0 } else { 20 },
        Some(inp) => {
            let in_total = u64le(&inp[40..48]);
            let out_total = u64le(&out[40..48]);
            if u64le(&out[0..8]) != u64le(&inp[0..8]) + 1 { return 21; }
            if out_total <= in_total { return 22; }
            let wbytes = match load_witness(0, Source::GroupInput) { Ok(w) => w, Err(_) => return 3 };
            let proof = match de_cum_q(&wbytes) { Some(p) => p, None => return 2 };
            if proof.total_old != in_total || proof.total_new != out_total { return 23; }
            if verify_cum_q_seeded(&out, &proof) { 0 } else { 20 }
        }
    }
}
