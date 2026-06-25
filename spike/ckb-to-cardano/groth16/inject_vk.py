#!/usr/bin/env python3
"""inject_vk.py - rewrite an Aiken g16 verifier test to use a CEREMONY-generated vk + proof.

The *_test.ak files hardcode a (vk, proof, public_inputs) triple and call the SAME on-chain `verify`
that cardano_bound / zk_chiral_mint / advance_ckbcert use. Re-running them with the ceremony key is a
real test that the on-chain verifier accepts ceremony-key proofs. This regenerates the test body from a
ceremony redeemer JSON (emitted by leap_prove/advance_prove/finalize_prove), preserving the original
//// header comment and the test function name.

Usage: inject_vk.py <redeemer.json> <test.ak>
"""
import json, re, sys

def main():
    rj, ak = sys.argv[1], sys.argv[2]
    d = json.load(open(rj))
    src = open(ak).read()

    # preserve leading //// comment block and the test fn name
    header_lines = []
    for line in src.splitlines():
        if line.startswith("////"):
            header_lines.append(line)
        else:
            break
    m = re.search(r"test\s+(\w+)\s*\(", src)
    fn = m.group(1) if m else "proof_verifies_onchain"

    vk = d["vk"]; pr = d["proof"]; pis = d["public_inputs_dec"]
    ic = ",".join(f'#"{x}"' for x in vk["ic"])
    pi = ", ".join(str(x) for x in pis)

    body = "\n".join(header_lines)
    if body:
        body += "\n"
    body += (
        "//// vk + proof below are from the REAL multi-party trusted-setup CEREMONY (see circuit/ceremony/).\n"
        "use g16/verifier.{VerifyingKey, Proof, verify}\n\n"
        f"test {fn}() {{\n"
        "  let vk =\n"
        "    VerifyingKey {\n"
        f'      alpha_g1: #"{vk["alpha_g1"]}", beta_g2: #"{vk["beta_g2"]}",\n'
        f'      gamma_g2: #"{vk["gamma_g2"]}", delta_g2: #"{vk["delta_g2"]}", ic: [{ic}],\n'
        "    }\n"
        f'  let proof = Proof {{ a: #"{pr["a"]}", b: #"{pr["b"]}", c: #"{pr["c"]}" }}\n'
        f"  verify(vk, proof, [{pi}])\n"
        "}\n"
    )
    open(ak, "w").write(body)
    print(f"injected ceremony vk ({len(vk['ic'])} ic, {len(pis)} public inputs) -> {ak}")

if __name__ == "__main__":
    main()
