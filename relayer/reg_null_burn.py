#!/usr/bin/env python3
"""reg_null_burn.py <witness_json> <state_file> [old_root] - burn_nullifier_registry insert witness for the
CKB-RELEASE leg (0x02). Key = blake2b256(0x02 || tx_body), where tx_body is the first lp field of the
produce_witness MKMapProof (== exactly what burn_gated_unlock_v2 reads + hashes). SMT identical to reg_nullifier_witness."""
import sys, os, json, hashlib
ZERO=b"\x00"*32; PRESENT=b"\x01"*32; PERSON=b"ckb-smt-null-set"
def h2(l,r): return hashlib.blake2b(l+r,digest_size=32,person=PERSON).digest()
E=[ZERO]
for _ in range(256): E.append(h2(E[-1],E[-1]))
def bit(k,bi): return (k[bi//8]>>(7-(bi%8)))&1
def subtree(h,keys):
    if not keys: return E[h]
    if h==0: return PRESENT
    bi=256-h
    return h2(subtree(h-1,[k for k in keys if bit(k,bi)==0]), subtree(h-1,[k for k in keys if bit(k,bi)==1]))
def siblings(present,K):
    sib=[None]*256; cur=list(present)
    for h in range(256,0,-1):
        bi=256-h; same,other=[],[]
        for k in cur: (same if bit(k,bi)==bit(K,bi) else other).append(k)
        sib[h-1]=subtree(h-1,other); cur=same
    return sib
def fold(value,key,sib):
    cur=value
    for d in range(256):
        cur=h2(sib[d],cur) if bit(key,255-d)==1 else h2(cur,sib[d])
    return cur
w=bytes.fromhex(json.load(open(sys.argv[1]))["witness"].removeprefix("0x"))
n=int.from_bytes(w[0:4],"little"); tx_body=w[4:4+n]
key=hashlib.blake2b(b"\x02"+tx_body,digest_size=32).digest()
keys=[bytes.fromhex(k.removeprefix("0x")) for k in json.load(open(sys.argv[2])).get("keys",[])] if os.path.exists(sys.argv[2]) else []
if key in keys: raise SystemExit("already inserted (replay)")
old_root=subtree(256,keys)
if len(sys.argv)>3:
    want=bytes.fromhex(sys.argv[3].removeprefix("0x"))
    if want!=old_root: raise SystemExit(f"root mismatch: computed {old_root.hex()} != live {want.hex()}")
sib=siblings(keys,key)
assert fold(ZERO,key,sib)==old_root, "non-membership check failed"
new_root=fold(PRESENT,key,sib)
assert subtree(256,keys+[key])==new_root, "insert check failed"
out={"key":"0x"+key.hex(),"witness":"0x"+(key+b"".join(sib)).hex(),"old_root":"0x"+old_root.hex(),"new_root":"0x"+new_root.hex(),"n_keys":len(keys),"tx_body_len":n}
json.dump(out, open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "onchain", "bg_reg_wit.json"), "w"))
print("key",key.hex()[:16],"| tx_body",n,"B | old_root",old_root.hex()[:16],"-> new_root",new_root.hex()[:16],"| n_keys",len(keys))
