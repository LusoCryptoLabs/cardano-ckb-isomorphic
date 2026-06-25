import json, urllib.request, hashlib, coincurve
RPC="https://testnet.ckb.dev"
def rpc(m,p):
    req=urllib.request.Request(RPC,data=json.dumps({"id":1,"jsonrpc":"2.0","method":m,"params":p}).encode(),headers={"content-type":"application/json","User-Agent":"Mozilla/5.0"})
    r=json.load(urllib.request.urlopen(req,timeout=25))
    if r.get("error"): raise RuntimeError(r["error"])
    return r["result"]
def ckbhash(b): return hashlib.blake2b(b,digest_size=32,person=b"ckb-default-hash").digest()
def u32(n): return n.to_bytes(4,'little')
def u64(n): return n.to_bytes(8,'little')
def fixvec(items): return u32(len(items))+b''.join(items)
def dynvec(items):
    n=len(items); off=4+4*n; offs=[]
    for it in items: offs.append(off); off+=len(it)
    return u32(off)+b''.join(u32(o) for o in offs)+b''.join(items)
table=dynvec
def molbytes(b): return u32(len(b))+b
def H(h): return bytes.fromhex(h[2:] if h.startswith("0x") else h)
k=json.load(open("/tmp/ckb_key.json")); priv=coincurve.PrivateKey(H(k["priv_hex"])); arg=H(k["lock_arg"])
CODE=H("9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8")
DEP_TX="0xf8de3bb47d055cdf460d93a2a6e1b05f7432f9777c8c474abf4eec1d4aee5d37"
LOCK_TXID="0x4923241abfd204a1aff2099b4cc0f2536d425d19936b54616f3a5263d4691bcb"
# the bound cell = LOCK_TXID output 0
tx=rpc("get_transaction",[LOCK_TXID])
bound_cap=int(tx["transaction"]["outputs"][0]["capacity"],16)
fee=100000; out_cap=bound_cap-fee
def script_mol(code,htype,args): return table([code, bytes([htype]), molbytes(args)])
lock=script_mol(CODE,1,arg)
def outpoint(txh,idx): return H(txh)+u32(idx)
cell_input=u64(0)+outpoint(LOCK_TXID,0)
cell_output=table([u64(out_cap), lock, b''])                 # back to a normal cell, no bound data
raw=table([u32(0), fixvec([outpoint(DEP_TX,0)+bytes([1])]), fixvec([]),
           fixvec([cell_input]), dynvec([cell_output]), dynvec([molbytes(b'')])])   # data empty => unbound
tx_hash=ckbhash(raw)
wa_zero=table([molbytes(b'\x00'*65), b'', b''])
h=hashlib.blake2b(digest_size=32,person=b"ckb-default-hash"); h.update(tx_hash); h.update(u64(len(wa_zero))); h.update(wa_zero)
sig=priv.sign_recoverable(h.digest(), hasher=lambda x:x)
wa=table([molbytes(sig), b'', b''])
txj={"version":"0x0","cell_deps":[{"out_point":{"tx_hash":DEP_TX,"index":"0x0"},"dep_type":"dep_group"}],
     "header_deps":[],"inputs":[{"since":"0x0","previous_output":{"tx_hash":LOCK_TXID,"index":"0x0"}}],
     "outputs":[{"capacity":hex(out_cap),"lock":{"code_hash":"0x"+CODE.hex(),"hash_type":"type","args":"0x"+arg.hex()},"type":None}],
     "outputs_data":["0x"],"witnesses":["0x"+wa.hex()]}
txid=rpc("send_transaction",[txj])
print("CKB_UNLOCK_TXID", txid)
json.dump({"ckb_unlock_txid":txid}, open("/tmp/ckb_unlock.json","w"))
