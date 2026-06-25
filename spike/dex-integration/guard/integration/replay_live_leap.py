#!/usr/bin/env python3
"""Resolve a REAL Pudge transaction into a ckb-debugger mock-tx by fetching every input + cell-dep (and
dep-group members) from the live RPC, so the DEPLOYED verifier binary can be re-executed locally on real
on-chain data. No mock: real tx, real cells, real witness (Mithril proof), real binary.
    python3 replay_live_leap.py <tx_hash> > mock.json
    ckb-debugger --tx-file mock.json --cell-type output --cell-index 0 --script-group-type type
"""
import json, sys, subprocess

RPC = "https://testnet.ckb.dev"

def rpc(method, params):
    body = json.dumps({"id": 1, "jsonrpc": "2.0", "method": method, "params": params})
    out = subprocess.run(["curl", "-sS", "-X", "POST", RPC, "-H", "content-type: application/json", "-d", body],
                         capture_output=True, text=True, timeout=40).stdout
    return json.loads(out)["result"]

def get_tx(h): return rpc("get_transaction", [h])["transaction"]

def cell_at(out_point):
    tx = get_tx(out_point["tx_hash"])
    idx = int(out_point["index"], 16)
    return tx["outputs"][idx], tx["outputs_data"][idx]

def parse_outpoint_vec(hexdata):  # molecule fixvec of OutPoint (36B each): 4B LE count + items
    b = bytes.fromhex(hexdata[2:])
    n = int.from_bytes(b[0:4], "little")
    out = []
    for i in range(n):
        off = 4 + i * 36
        item = b[off:off + 36]
        out.append({"tx_hash": "0x" + item[0:32].hex(), "index": hex(int.from_bytes(item[32:36], "little"))})
    return out

def mock_cell(out_point, output, data):
    return {"cell_dep": {"out_point": out_point, "dep_type": "code"}, "output": output, "data": data, "header": None}

def main():
    tx = get_tx(sys.argv[1])
    mock_inputs, mock_deps = [], []
    for inp in tx["inputs"]:
        o, d = cell_at(inp["previous_output"])
        mock_inputs.append({"input": inp, "output": o, "data": d, "header": None})
    for dep in tx["cell_deps"]:
        o, d = cell_at(dep["out_point"])
        # the dep-group cell itself (keep its real dep_type) + each member as a code cell-dep
        mock_deps.append({"cell_dep": dep, "output": o, "data": d, "header": None})
        if dep["dep_type"] == "dep_group":
            for m in parse_outpoint_vec(d):
                mo, md = cell_at(m)
                mock_deps.append(mock_cell(m, mo, md))
    mock = {
        "mock_info": {"inputs": mock_inputs, "cell_deps": mock_deps, "header_deps": [], "extensions": []},
        "tx": {k: tx[k] for k in ("version", "cell_deps", "header_deps", "inputs", "outputs", "outputs_data", "witnesses")},
    }
    json.dump(mock, sys.stdout)

if __name__ == "__main__":
    main()
