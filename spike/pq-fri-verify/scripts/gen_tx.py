#!/usr/bin/env python3
"""Build a ckb-debugger mock transaction that runs the `quartic_witness` lock script with the post-quantum
proof supplied as the input's witness - the real on-chain shape. Usage:
    python3 gen_tx.py <script_binary> <proof_bin> > tx.json
    ckb-debugger --tx-file tx.json --cell-index 0 --cell-type input --script-group-type lock
"""
import hashlib, json, sys

def ckbhash(data: bytes) -> str:
    h = hashlib.blake2b(digest_size=32, person=b"ckb-default-hash")
    h.update(data)
    return "0x" + h.hexdigest()

binary = open(sys.argv[1], "rb").read()
proof  = open(sys.argv[2], "rb").read()

code_hash = ckbhash(binary)                       # hash_type "data2" ⇒ code_hash = ckbhash(cell data)
lock = {"code_hash": code_hash, "hash_type": "data2", "args": "0x"}
dummy_lock = {"code_hash": "0x" + "00" * 32, "hash_type": "data2", "args": "0x"}

in_prevout  = {"tx_hash": "0x" + "00" * 31 + "01", "index": "0x0"}
dep_outpoint = {"tx_hash": "0x" + "00" * 31 + "02", "index": "0x0"}
cap = "0x100000000000"                            # generous capacity (shannons)

cell = {"capacity": cap, "lock": lock, "type": None}                 # the input cell guarded by our script
dep_cell = {"capacity": cap, "lock": dummy_lock, "type": None}       # the cell_dep that carries the script code

mock = {
    "mock_info": {
        "inputs": [
            {"input": {"since": "0x0", "previous_output": in_prevout}, "output": cell, "data": "0x", "header": None}
        ],
        "cell_deps": [
            {"cell_dep": {"out_point": dep_outpoint, "dep_type": "code"},
             "output": dep_cell, "data": "0x" + binary.hex(), "header": None}
        ],
        "header_deps": [],
        "extensions": [],
    },
    "tx": {
        "version": "0x0",
        "cell_deps": [{"out_point": dep_outpoint, "dep_type": "code"}],
        "header_deps": [],
        "inputs": [{"since": "0x0", "previous_output": in_prevout}],
        "outputs": [cell],
        "outputs_data": ["0x"],
        "witnesses": ["0x" + proof.hex()],          # <-- the post-quantum proof, as witness data
    },
}
json.dump(mock, sys.stdout)
