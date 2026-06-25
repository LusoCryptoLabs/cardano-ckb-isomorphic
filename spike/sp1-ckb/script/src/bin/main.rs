//! SP1 host: mine a small CKB PoW header chain, then either execute (cycle count) or generate + verify a
//! real core-STARK proof of `verify_chain` running in the zkVM - the post-quantum forward-leg prover, run
//! locally in CPU mode. Usage: `cargo run --release -- --execute|--prove [--blocks N] [--bits K]`.
use clap::Parser;
use ckb_chain_lib::{block_hash, compact_to_target, pow_value, Header};
use primitive_types::U256;

fn hex8(b: &[u8; 32]) -> String {
    b[..8].iter().map(|x| format!("{:02x}", x)).collect()
}
use sp1_sdk::{
    blocking::{ProveRequest, Prover, ProverClient},
    include_elf, Elf, ProvingKey, SP1Stdin,
};
use std::time::Instant;

const CKB_ELF: Elf = include_elf!("ckb-chain-program");

#[derive(Parser, Debug)]
struct Args {
    #[arg(long)]
    execute: bool,
    #[arg(long)]
    prove: bool,
    /// number of blocks in the chain to mine + verify
    #[arg(long, default_value = "32")]
    blocks: u64,
    /// PoW difficulty: required leading zero bits of the Eaglesong output (multiple of 8; ~2^bits tries/block)
    #[arg(long, default_value = "8")]
    bits: u32,
    /// corrupt one block before proving (the chain becomes invalid ⇒ the guest panics ⇒ it is unprovable):
    /// demonstrates you cannot make a proof of a false statement
    #[arg(long)]
    tamper: bool,
    /// generate a COMPRESSED (recursion) proof - the constant-size, on-chain-relevant proof - instead of core
    #[arg(long)]
    compressed: bool,
}

/// Mine a valid chain: for each block, search nonces until the Eaglesong PoW meets the compact target.
fn mine_chain(genesis_parent: [u8; 32], compact_target: u32, blocks: u64) -> Vec<Header> {
    let target = compact_to_target(compact_target);
    let mut headers = Vec::with_capacity(blocks as usize);
    let mut prev = genesis_parent;
    for number in 0..blocks {
        let mut nonce = 0u128;
        loop {
            let h = Header { parent_hash: prev, number, compact_target, nonce };
            if pow_value(&h) <= target {
                prev = block_hash(&h);
                headers.push(h);
                break;
            }
            nonce += 1;
        }
    }
    headers
}

fn main() {
    sp1_sdk::utils::setup_logger();
    let args = Args::parse();
    if args.execute == args.prove {
        eprintln!("Error: specify exactly one of --execute or --prove");
        std::process::exit(1);
    }

    let genesis_parent = [0u8; 32];
    // compact target for difficulty ~2^(256-bits): target = 1 << (256-bits) = mantissa 1, exponent 35-bits/8
    let compact_target: u32 = ((35 - args.bits / 8) << 24) | 1;

    let t0 = Instant::now();
    let mut headers = mine_chain(genesis_parent, compact_target, args.blocks);
    println!("mined {} blocks (Eaglesong PoW, difficulty {} bits, compact 0x{:08x}) in {:?}",
        args.blocks, args.bits, compact_target, t0.elapsed());
    if args.tamper {
        let mid = headers.len() / 2;
        headers[mid].nonce = headers[mid].nonce.wrapping_add(1); // breaks block `mid`'s PoW + child linkage
        println!("TAMPERED block {} - chain is now invalid", mid);
    }

    let mut stdin = SP1Stdin::new();
    stdin.write(&genesis_parent);
    stdin.write(&compact_target);
    stdin.write(&headers);

    let client = ProverClient::from_env();

    if args.execute {
        let (mut output, report) = client.execute(CKB_ELF, stdin).run().unwrap();
        println!("executed OK - cycles: {}", report.total_instruction_count());
        // decode the public checkpoint the proof attests (same order the guest committed)
        let _genesis: [u8; 32] = output.read();
        let _ct: u32 = output.read();
        let chain_root: [u8; 32] = output.read();
        let _tip: [u8; 32] = output.read();
        let total_work_be: [u8; 32] = output.read();
        let count: u32 = output.read();
        let total_work = U256::from_big_endian(&total_work_be);
        println!("attested checkpoint: chain_root=0x{}… total_work={} count={}",
            hex8(&chain_root), total_work, count);

        // --- wire into a checkpoint ADVANCE (sp1-ckb -> checkpoint) ---
        // in-state: epoch 7, some prior root, prior total; out-state: the SP1-attested (root, work) at epoch 8
        let in_epoch = 7u64;
        let in_total = U256::from(1u64); // a lighter prior chain
        let out_epoch = in_epoch + 1;
        let epoch_ok = out_epoch == in_epoch + 1;       // monotone epoch
        let heavier = total_work > in_total;             // heaviest-chain guard
        println!("checkpoint advance epoch {}->{}  heavier={}  => {}",
            in_epoch, out_epoch, heavier,
            if epoch_ok && heavier { "ACCEPT (new checkpoint = the SP1-attested chain_root/total_work)" }
            else { "REJECT" });
        println!("note: on-chain this advance is gated by VERIFYING this SP1 proof - native ~2.3G cyc, or the \
            recursion in spike/pq-recursion (~300M). The data flow + transition rules are wired here.");
    } else {
        let pk = client.setup(CKB_ELF).expect("setup");
        let t1 = Instant::now();
        let proof = if args.compressed {
            client.prove(&pk, stdin).compressed().run().expect("prove")
        } else {
            client.prove(&pk, stdin).run().expect("prove")
        };
        let prove_t = t1.elapsed();
        println!("PROVED ({}) in {:?}", if args.compressed { "compressed" } else { "core" }, prove_t);
        // count exactly how many Poseidon2-KoalaBear permutations the VERIFY performs
        p3_poseidon2::poseidon2_count_reset();
        let vresult = client.verify(&proof, pk.verifying_key(), None);
        let n_perms = p3_poseidon2::poseidon2_count();
        match vresult {
            Ok(()) => println!(
                "VERIFIED - a real post-quantum STARK proof of CKB consensus, made + checked on this box."),
            Err(e) => println!(
                "REJECTED - proof does not verify as a successful run ({e}); an invalid chain is unprovable."),
        }
        const CKBVM_CYC_PER_PERM: u64 = 26_157; // measured in spike/sp1-verify-cost
        println!("POSEIDON2 PERMS in verify: {n_perms}");
        println!("=> on-chain CKB-VM cost @ {CKBVM_CYC_PER_PERM} cyc/perm = {} cycles ({:.1}M)",
            n_perms * CKBVM_CYC_PER_PERM, (n_perms * CKBVM_CYC_PER_PERM) as f64 / 1e6);
    }
}
