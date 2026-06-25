#!/usr/bin/env python3
"""Build a ckb-debugger mock transaction for a CHECKPOINT ADVANCE guarded by the post-quantum `checkpoint`
type script: an input checkpoint cell (data = old state) and an output checkpoint cell (data = new state),
both carrying the type script, with the post-quantum proof in the input witness.

    python3 gen_checkpoint_tx.py <checkpoint_bin> <proof_bin> <in48_bin> <out48_bin> > tx.json
    ckb-debugger --tx-file tx.json --cell-index 0 --cell-type input --script-group-type type
"""
import hashlib, json, sys

def ckbhash(d: bytes) -> str:
    h = hashlib.blake2b(digest_size=32, person=b"ckb-default-hash"); h.update(d); return "0x" + h.hexdigest()

binary = open(sys.argv[1], "rb").read()
proof  = open(sys.argv[2], "rb").read()
cp_in  = open(sys.argv[3], "rb").read()
cp_out = open(sys.argv[4], "rb").read()

type_script = {"code_hash": ckbhash(binary), "hash_type": "data2", "args": "0x"}
dummy_lock  = {"code_hash": "0x" + "00" * 32, "hash_type": "data2", "args": "0x"}
in_prevout  = {"tx_hash": "0x" + "00" * 31 + "01", "index": "0x0"}
dep_outpoint = {"tx_hash": "0x" + "00" * 31 + "02", "index": "0x0"}
cap = "0x100000000000"

in_cell  = {"capacity": cap, "lock": dummy_lock, "type": type_script}
out_cell = {"capacity": cap, "lock": dummy_lock, "type": type_script}
dep_cell = {"capacity": cap, "lock": dummy_lock, "type": None}

mock = {
    "mock_info": {
        "inputs": [{"input": {"since": "0x0", "previous_output": in_prevout},
                    "output": in_cell, "data": "0x" + cp_in.hex(), "header": None}],
        "cell_deps": [{"cell_dep": {"out_point": dep_outpoint, "dep_type": "code"},
                       "output": dep_cell, "data": "0x" + binary.hex(), "header": None}],
        "header_deps": [], "extensions": [],
    },
    "tx": {
        "version": "0x0",
        "cell_deps": [{"out_point": dep_outpoint, "dep_type": "code"}],
        "header_deps": [],
        "inputs": [{"since": "0x0", "previous_output": in_prevout}],
        "outputs": [out_cell],
        "outputs_data": ["0x" + cp_out.hex()],
        "witnesses": ["0x" + proof.hex()],
    },
}
json.dump(mock, sys.stdout)
