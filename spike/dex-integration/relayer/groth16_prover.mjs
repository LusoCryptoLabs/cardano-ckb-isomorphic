// groth16_prover.mjs - the CKB→Cardano ProofProvider: produce the Groth16 (BLS12-381, CIP-0381) proof the
// deployed `cardano_bound` verifier consumes, by driving the existing arkworks prover
// (spike/ckb-to-cardano/prover). That prover emits a fixture { vk, proof{a,b,c}, public_inputs[3] } in the
// exact compressed hex the Aiken verifier expects. The 3 public inputs bind the consensus statement
// (header_root, seal_outpoint, commitment); the prover's circuit is currently the SquaresCircuit placeholder
// - swap it for the real consensus circuit in the prover before mainnet (the proof FORMAT is already real).
import { execFile } from "node:child_process";
import { readFile } from "node:fs/promises";
import { promisify } from "node:util";
const run = promisify(execFile);

/** Parse the prover's stdout (a JSON object: vk / proof / public_inputs). */
export function parseFixture(text) {
  // the prover prints the fixture as a JSON object (possibly with eprintln diagnostics on stderr only)
  const start = text.indexOf("{");
  const end = text.lastIndexOf("}");
  if (start < 0 || end < 0) throw new Error("no fixture JSON in prover output");
  const j = JSON.parse(text.slice(start, end + 1));
  if (!j.proof || !j.vk || !j.public_inputs) throw new Error("fixture missing vk/proof/public_inputs");
  return j;
}

/**
 * @param {{ proverDir?: string, fixturePath?: string }} opts
 *   proverDir   - run `cargo run --release` there to generate a fresh proof (real, slow).
 *   fixturePath - read a pre-generated fixture.json instead (fast; for wiring/tests).
 */
export function groth16Provider({ proverDir, fixturePath } = {}) {
  return {
    async proveCkbToCardano(event) {
      // bind the leap to the public inputs (header_root, seal_outpoint=event.nonce, commitment). The current
      // placeholder circuit ignores them at the constraint level; the real consensus circuit will enforce them.
      void event;
      let fixture;
      if (fixturePath) {
        fixture = parseFixture(await readFile(fixturePath, "utf8"));
      } else if (proverDir) {
        const { stdout } = await run("cargo", ["run", "--release", "--quiet"], { cwd: proverDir, maxBuffer: 16 * 1024 * 1024 });
        fixture = parseFixture(stdout);
      } else {
        throw new Error("groth16Provider: set proverDir (generate) or fixturePath (reuse)");
      }
      // the relayer hands this whole fixture to cardano_bound's redeemer via the leap-in mint plan.
      return fixture;
    },
  };
}
