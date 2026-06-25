#!/usr/bin/env python3
"""Emit the VerifyingKey as Plutus-Data CBOR - the compile-time `vk` parameter for zk_chiral_mint /
cardano_bound. Reads a relay_bind proof (its `vk` field) and writes the CBOR hex (no trailing newline).

  python3 gen_vk_param.py <proof.json> <out.cbor>
"""
import json
import sys
from dataclasses import dataclass
from typing import List
from pycardano import PlutusData
from pycardano.serialization import ByteString


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


def main() -> int:
    proof, out = sys.argv[1], sys.argv[2]
    v = json.load(open(proof))["vk"]
    vk = VK(B(v["alpha_g1"]), B(v["beta_g2"]), B(v["gamma_g2"]), B(v["delta_g2"]), [B(x) for x in v["ic"]])
    with open(out, "w") as f:
        f.write(vk.to_cbor_hex())
    print(f"vk param CBOR -> {out} ({len(vk.to_cbor_hex()) // 2} bytes)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
