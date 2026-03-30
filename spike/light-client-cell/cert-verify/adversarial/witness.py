"""Parse the MWIT witness layout into field offsets so the adversarial suite can
mutate exact bytes. Mirrors transcode_witness.rs / cert-verify parse()."""
import struct

def parse_layout(w):
    assert w[0:4] == b"MWIT", "bad magic"
    o = {}
    p = 4
    o["signed_message"] = (p, 32); p += 32
    o["avk_root"] = (p, 32); p += 32
    o["total"] = (p, 8); p += 8
    o["k"] = (p, 8); p += 8
    np_ = w[p]; o["np_off"] = p; p += 1
    parts = []
    for _ in range(np_):
        kl = w[p]; p += 1
        key = w[p:p+kl]; p += kl
        vl = struct.unpack_from("<H", w, p)[0]; p += 2
        val_off = p; val = w[p:p+vl]; p += vl
        parts.append({"key": key, "val_off": val_off, "vlen": vl})
    o["parts"] = parts
    ns = w[p]; o["ns_off"] = p; p += 1
    signers = []
    for _ in range(ns):
        sigma_off = p; p += 48
        mvk_off = p; p += 96
        stake_off = p; p += 8
        nidx = struct.unpack_from("<H", w, p)[0]; p += 2
        idx_off = p; p += 4*nidx
        signers.append({"sigma_off": sigma_off, "mvk_off": mvk_off,
                        "stake_off": stake_off, "nidx": nidx, "idx_off": idx_off})
    o["signers"] = signers
    o["nr_leaves_off"] = p; p += 2
    nm = w[p]; o["nm_off"] = p; p += 1
    o["mindices_off"] = p; p += 2*nm
    nb = w[p]; o["nb_off"] = p; p += 1
    o["bvals_off"] = p; p += 32*nb; o["nb"] = nb
    o["tx_root"] = (p, 32); p += 32
    o["end"] = p
    return o

def flip(w, off):
    b = bytearray(w); b[off] ^= 0xFF; return bytes(b)

def part_off(layout, keyname):
    for pt in layout["parts"]:
        if pt["key"] == keyname:
            return pt["val_off"], pt["vlen"]
    return None
