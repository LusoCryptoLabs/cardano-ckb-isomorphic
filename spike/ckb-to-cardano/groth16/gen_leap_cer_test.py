#!/usr/bin/env python3
"""Generate lib/g16/leap_cer_test.ak: the new (ceremony) leap vk ACCEPTS the ceremony proof and REJECTS the
seeded proof (same public inputs) -> the seeded-vk forge hole is closed (a forger's seeded proof no longer verifies)."""
import json, os
HERE = os.path.dirname(os.path.abspath(__file__))
CER = os.path.join(HERE, "..", "circuit", "ceremony")
cer = json.load(open(os.path.join(CER, "leap_bound_windowed_redeemer.json")))          # ceremony (deployed)
seed = json.load(open(os.path.join(CER, "leap_bound_windowed_redeemer.SEEDED.bak.json")))  # old seeded

def vk_ak(vk):
    ic = ",\n      ".join(f'#"{x}"' for x in vk["ic"])
    return ("VerifyingKey {\n"
            f'    alpha_g1: #"{vk["alpha_g1"]}",\n'
            f'    beta_g2: #"{vk["beta_g2"]}",\n'
            f'    gamma_g2: #"{vk["gamma_g2"]}",\n'
            f'    delta_g2: #"{vk["delta_g2"]}",\n'
            f'    ic: [\n      {ic},\n    ],\n'
            "  }")

def proof_ak(p):
    return f'Proof {{ a: #"{p["a"]}", b: #"{p["b"]}", c: #"{p["c"]}" }}'

pi = ", ".join(cer["public_inputs_dec"])   # ceremony + seeded proofs share the same public inputs (same witness/window)
out = f'''//// LC3: the seeded-vk forge hole is CLOSED. cardano_bound is now baked with the CEREMONY leap vk (alpha
//// {cer["vk"]["alpha_g1"][:16]}..., a real 3+3-contributor MPC, toxic waste destroyed). This verifier ACCEPTS the
//// ceremony proof and REJECTS the old seeded proof (same public inputs) -- so a forger holding the public seed-7
//// toxic waste can no longer mint: their seeded proof no longer verifies under the deployed vk.
use g16/verifier.{{VerifyingKey, Proof, verify}}

fn ceremony_vk() -> VerifyingKey {{
  {vk_ak(cer["vk"])}
}}

const leap_pi: List<Int> = [{pi}]

test ceremony_leap_proof_verifies() {{
  verify(ceremony_vk(), {proof_ak(cer["proof"])}, leap_pi)
}}

// the OLD seeded proof (made under the seed-7 vk) must be REJECTED by the ceremony verifier.
test seeded_leap_proof_rejected_under_ceremony_vk() fail {{
  verify(ceremony_vk(), {proof_ak(seed["proof"])}, leap_pi)
}}
'''
dst = os.path.join(HERE, "lib", "g16", "leap_cer_test.ak")
open(dst, "w").write(out)
print("wrote", dst)
print("ceremony vk.alpha", cer["vk"]["alpha_g1"][:16], "| seeded proof.a", seed["proof"]["a"][:16])
