#!/usr/bin/env python3
"""Assemble a FINALIZE mock-tx for ckb-debugger from the generated dataset, so the REAL compiled verifier
runs over a witness the relayer's encoder produces. FINALIZE = the bound cell is an INPUT with NO matching
output; its witness.input_type = the proof; a cell-dep carries "LCKP"||cert_root. We target the type group.
    python3 assemble.py <dataset.json> <verifier_bin> > mock.json
"""
import json, sys, hashlib

def ckbhash(b):  # blake2b-256 with CKB personalization
    return hashlib.blake2b(b, digest_size=32, person=b"ckb-default-hash").digest()

def h(x):  # bytes/hex-str -> 0x hex
    if isinstance(x, bytes): return "0x" + x.hex()
    return x if x.startswith("0x") else "0x" + x

def main():
    ds = json.load(open(sys.argv[1]))
    vbin = open(sys.argv[2], "rb").read()
    code_hash = ckbhash(vbin)
    witness = bytes.fromhex(ds["witness"])
    bound_data = "0x" + ds["bound_data"]
    cert_root = bytes.fromhex(ds["cert_root"])
    ckpt_data = "0x" + b"LCKP".hex() + cert_root.hex()

    dummy_lock = {"code_hash": "0x" + "00"*32, "hash_type": "data", "args": "0x"}
    verifier_type = {"code_hash": "0x" + code_hash.hex(), "hash_type": "data1", "args": "0x"}

    op = lambda tag, i=0: {"tx_hash": "0x" + (tag*32)[:64], "index": hex(i)}
    bound_op, ckpt_op, ver_op = op("a1"), op("c0"), op("ef")

    # WitnessArgs molecule (table: lock, input_type, output_type), input_type = Bytes(witness)
    def witness_args(input_type):
        lock, otype = b"", b""
        itype = len(input_type).to_bytes(4, "little") + input_type   # Bytes (fixvec)
        fields = [lock, itype, otype]
        hdr = 4 * (1 + len(fields))
        offs, off = [], hdr
        for f in fields: offs.append(off); off += len(f)
        out = off.to_bytes(4, "little") + b"".join(o.to_bytes(4, "little") for o in offs) + b"".join(fields)
        return out
    wa = "0x" + witness_args(witness).hex()

    cell = lambda cap, lock, data, typ=None: {"capacity": hex(cap), "lock": lock, "type": typ}
    mock = {
        "mock_info": {
            "inputs": [{
                "input": {"since": "0x0", "previous_output": bound_op},
                "output": cell(0x2540be400, dummy_lock, bound_data, verifier_type),   # the BOUND cell (FINALIZE)
                "data": bound_data, "header": None,
            }],
            "cell_deps": [
                {"cell_dep": {"out_point": ckpt_op, "dep_type": "code"},
                 "output": cell(0x2540be400, dummy_lock, ckpt_data), "data": ckpt_data, "header": None},   # "LCKP"||root
                {"cell_dep": {"out_point": ver_op, "dep_type": "code"},
                 "output": cell(0x9502f9000, dummy_lock, h(vbin.hex())), "data": h(vbin.hex()), "header": None},  # verifier code
            ],
            "header_deps": [], "extensions": [],
        },
        "tx": {
            "version": "0x0",
            "cell_deps": [
                {"out_point": ckpt_op, "dep_type": "code"},
                {"out_point": ver_op, "dep_type": "code"},
            ],
            "header_deps": [],
            "inputs": [{"since": "0x0", "previous_output": bound_op}],
            "outputs": [],          # FINALIZE: bound cell NOT recreated
            "outputs_data": [],
            "witnesses": [wa],
        },
    }
    json.dump(mock, sys.stdout)

if __name__ == "__main__":
    main()
