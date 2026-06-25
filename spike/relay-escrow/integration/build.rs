// build.rs - make `cargo test` self-contained. The integration tests load the compiled CKB contract from
// `../target/riscv64imac-unknown-none-elf/release/relay_escrow`; on a clean checkout that file does not exist,
// so every test panics in 0.00s at `fs::read(BIN).expect("build relay_escrow first")` before any CKB-VM logic
// runs (a false failure that looks like a defect). This script cross-compiles the contract first so the suite
// is green from a clean tree.
use std::path::Path;
use std::process::Command;

const CONTRACT_DIR: &str = ".."; // the relay-escrow contract crate is the parent of this integration crate
const TARGET: &str = "riscv64imac-unknown-none-elf";
const BIN: &str = "relay_escrow";

fn main() {
    let manifest = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
    let contract = Path::new(&manifest).join(CONTRACT_DIR);
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed={}/src", contract.display());
    println!("cargo:rerun-if-changed={}/Cargo.toml", contract.display());

    // Build the contract for its OWN riscv target, ignoring the host integration build's flags/target so they
    // cannot mis-target the contract. The contract lands exactly where the test reads it.
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let status = Command::new(&cargo)
        .args(["build", "--release", "--target", TARGET])
        .current_dir(&contract)
        .env_remove("RUSTFLAGS")
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        .env_remove("CARGO_BUILD_TARGET")
        .env_remove("CARGO_BUILD_RUSTFLAGS")
        .env_remove("CARGO_TARGET_DIR")
        .status()
        .unwrap_or_else(|e| panic!("could not spawn `{cargo} build` for the {BIN} contract at {}: {e}", contract.display()));

    if !status.success() {
        panic!(
            "building the {BIN} CKB contract ({TARGET}) failed. Add the target with \
             `rustup target add {TARGET}` and ensure the CKB riscv toolchain is present, then re-run `cargo test`."
        );
    }
    let bin = contract.join("target").join(TARGET).join("release").join(BIN);
    assert!(bin.exists(), "contract built but binary not found at {}", bin.display());
}
