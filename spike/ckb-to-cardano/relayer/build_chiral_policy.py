#!/usr/bin/env python3
"""Build the deployable zk_chiral_mint minting policy: apply the (vk, ft_name) compile-time params to the
blueprint and emit the final policy id + applied compiledCode. Done in Python (subprocess -> aiken) to avoid
fragile shell quoting. Run inside WSL where aiken + pycardano live.

  python3 build_chiral_policy.py <proof.json> <ft_name_ascii> <out_applied.json>
"""
import json
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import List
from pycardano import PlutusData
from pycardano.serialization import ByteString

AIKEN = "/root/.aiken/bin/aiken"
GROTH16 = Path(__file__).resolve().parents[1] / "groth16"   # the aiken project (has plutus.json)


def B(h: str) -> ByteString:
    return ByteString(bytes.fromhex(h.replace("0x", "")))


@dataclass
class VK(PlutusData):
    CONSTR_ID = 0
    alpha_g1: ByteString
    beta_g2: ByteString
    gamma_g2: ByteString
    delta_g2: ByteString
    ic: List[ByteString]


def aiken_apply(cbor_hex: str, in_bp: str | None, out_bp: str):
    cmd = [AIKEN, "blueprint", "apply", "-m", "zk_chiral_mint"]
    if in_bp:
        cmd += ["-i", in_bp]
    cmd += [cbor_hex, "-o", out_bp]
    r = subprocess.run(cmd, cwd=GROTH16, capture_output=True, text=True)
    if r.returncode != 0:
        raise SystemExit(f"aiken apply failed: {r.stdout}\n{r.stderr}")


def main() -> int:
    proof_path, ft_ascii, out_path = sys.argv[1], sys.argv[2], sys.argv[3]
    v = json.load(open(proof_path))["vk"]
    vk_cbor = VK(B(v["alpha_g1"]), B(v["beta_g2"]), B(v["gamma_g2"]), B(v["delta_g2"]),
                 [B(x) for x in v["ic"]]).to_cbor_hex()
    # ft_name as Plutus Data = a CBOR bytestring; small (<24 bytes) -> 0x40|len header.
    name = ft_ascii.encode()
    assert len(name) < 24, "ft_name too long for the simple CBOR header path"
    ft_cbor = bytes([0x40 | len(name)]).hex() + name.hex()

    tmp = tempfile.mkdtemp()
    bp1, bp2 = f"{tmp}/bp1.json", f"{tmp}/bp2.json"
    aiken_apply(vk_cbor, None, bp1)        # param 1: vk
    aiken_apply(ft_cbor, bp1, bp2)         # param 2: ft_name
    bp = json.load(open(bp2))
    # select the zk_chiral_mint policy by EXACT title - the blueprint has several `.mint` validators.
    cands = [x for x in bp["validators"] if x["title"] == "zk_chiral_mint.zk_chiral_mint.mint"]
    if not cands:
        raise SystemExit("zk_chiral_mint.zk_chiral_mint.mint not in applied blueprint; titles: "
                         + ", ".join(sorted(x["title"] for x in bp["validators"] if x["title"].endswith(".mint"))))
    val = cands[0]
    rec = {"policy_id": val["hash"], "compiledCode": val["compiledCode"],
           "ft_name_hex": name.hex(), "vk_cbor_bytes": len(vk_cbor) // 2}
    Path(out_path).write_text(json.dumps(rec, indent=2))
    print(f"policy_id: {val['hash']}")
    print(f"compiledCode: {len(val['compiledCode']) // 2} bytes  ft_name: {name.hex()}")
    print(f"saved -> {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
