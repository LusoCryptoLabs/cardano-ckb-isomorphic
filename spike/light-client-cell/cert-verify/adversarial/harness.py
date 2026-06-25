#!/usr/bin/env python3
"""ckb-debugger mock-tx harness for the cert-verify adversarial suite.
Builds a MockTransaction JSON placing the verifier as the type script of an
output (deploy) or with a group input/output checkpoint (advance), plus cellDeps
carrying the MWIT witness and (optionally) an AVK checkpoint cell. Runs the chosen
binary under ckb-debugger and returns its exit (script) code."""
import json, subprocess, os, hashlib

DBG = os.environ.get("CKB_DEBUGGER", "ckb-debugger")
HERE = os.path.dirname(os.path.abspath(__file__))

def h(b):  # bytes -> 0x hex
    return "0x" + (b.hex() if isinstance(b, (bytes, bytearray)) else b)

def th(n):  # deterministic 32-byte tx_hash from a tag
    return "0x" + hashlib.sha256(n.encode()).hexdigest()

def ckbhash(b):  # blake2b-256 with ckb personalization
    return hashlib.blake2b(b, digest_size=32, person=b"ckb-default-hash").digest()

ANY_LOCK = {"code_hash": "0x" + "11"*32, "hash_type": "data1", "args": "0x"}

def cell_dep(tag, data, typ=None, cap=0x1000000000):
    op = {"tx_hash": th(tag), "index": "0x0"}
    return {
        "cell_dep": {"out_point": op, "dep_type": "code"},
        "output": {"capacity": hex(cap), "lock": ANY_LOCK, "type": typ},
        "data": h(data), "header": None,
    }, {"out_point": op, "dep_type": "code"}

def input_cell(tag, data, typ=None, cap=0x10000000000):
    op = {"tx_hash": th(tag), "index": "0x0"}
    return {
        "input": {"since": "0x0", "previous_output": op},
        "output": {"capacity": hex(cap), "lock": ANY_LOCK, "type": typ},
        "data": h(data), "header": None,
    }, {"since": "0x0", "previous_output": op}

def run(binpath, *, celldeps=(), group_in=None, out_type=None, out_data=b"",
        group="type", cell_type="output", extra_outs=(), extra_ins=()):
    """celldeps: list of (data, type) tuples. group_in: (data,type) for an input
    whose `group` script is the verifier. out_type/out_data: the output cell.
    extra_outs / extra_ins: list of (data, type) sibling cells; type=None means the
    verifier type itself (used to test the singleton 'one group cell' guard)."""
    mock_cell_deps, tx_cell_deps = [], []
    # the verifier binary is itself a cellDep so its code_hash resolves
    code = open(binpath, "rb").read()
    cverif = ckbhash(code)
    mc, tc = cell_dep("VERIFIERCODE", code)
    mock_cell_deps.append(mc); tx_cell_deps.append(tc)
    for i, (data, typ) in enumerate(celldeps):
        mc, tc = cell_dep(f"dep{i}", data, typ)
        mock_cell_deps.append(mc); tx_cell_deps.append(tc)

    mock_inputs, tx_inputs = [], []
    outputs, outputs_data = [], []

    # The verifier runs as the `type` script. Attach it to the output (deploy/standalone)
    # and/or to a group input (advance). code_hash = the real CKB hash of the binary.
    verifier_script = {"code_hash": h(cverif), "hash_type": "data1", "args": "0x"}

    if group_in is not None:
        gi_data, _ = group_in
        mc, tc = input_cell("groupin", gi_data, typ=verifier_script)
        mock_inputs.append(mc); tx_inputs.append(tc)
    else:
        # need at least one input for a valid tx
        mc, tc = input_cell("filler", b"")
        mock_inputs.append(mc); tx_inputs.append(tc)
    # SEC (singleton attack): extra inputs that ALSO carry the verifier type join the same script group.
    for j, (data, typ) in enumerate(extra_ins):
        mc, tc = input_cell(f"groupin_x{j}", data, typ=(typ if typ is not None else verifier_script))
        mock_inputs.append(mc); tx_inputs.append(tc)

    # output carrying the verifier type
    outputs.append({"capacity": "0x100000000000", "lock": ANY_LOCK,
                    "type": out_type if out_type is not None else verifier_script})
    outputs_data.append(h(out_data))
    # SEC (singleton attack): extra outputs wearing the verifier type are siblings in the SAME group;
    # the singleton guard must reject them so a forged checkpoint can't ride alongside the valid one.
    for (data, typ) in extra_outs:
        outputs.append({"capacity": "0x100000000000", "lock": ANY_LOCK,
                        "type": typ if typ is not None else verifier_script})
        outputs_data.append(h(data))

    mock = {
        "mock_info": {"inputs": mock_inputs, "cell_deps": mock_cell_deps, "header_deps": []},
        "tx": {"version": "0x0", "cell_deps": tx_cell_deps, "header_deps": [],
               "inputs": tx_inputs, "outputs": outputs, "outputs_data": outputs_data,
               "witnesses": []},
    }
    path = "/tmp/advsuite/_tx.json"
    with open(path, "w") as f:
        json.dump(mock, f)
    cmd = [DBG, "--tx-file", path,
           "-s", group, "-i", "0", "-t", cell_type, "--mode", "fast"]
    p = subprocess.run(cmd, capture_output=True, text=True)
    out = p.stdout + p.stderr
    # success: ckb-debugger prints cycle stats and returns 0.
    # failure: it prints  Error: ValidationFailure("<hash>", CODE)  (the script's return code).
    import re
    m = re.search(r'ValidationFailure\("[^"]*",\s*(-?\d+)\)', out)
    if m:
        return int(m.group(1)), out
    # newer ckb-debugger prints `Run result: N` (N is the script's i8 return) instead of ValidationFailure
    m2 = re.search(r'Run result:\s*(-?\d+)', out)
    if m2:
        return int(m2.group(1)), out
    if p.returncode == 0:
        return 0, out
    return p.returncode, out

if __name__ == "__main__":
    # baseline smoke test: standalone with the valid witness -> 0
    w = open("/tmp/cert_witness.bin", "rb").read()
    code, out = run("/tmp/cv_standalone.bin", celldeps=[(w, None)])
    print("baseline standalone valid witness -> exit", code)
    if code != 0:
        print(out[-800:])
