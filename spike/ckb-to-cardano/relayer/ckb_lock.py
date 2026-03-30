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
# pick the 100000 CKB cell
cells=rpc("get_cells",[{"script":{"code_hash":"0x"+CODE.hex(),"hash_type":"type","args":"0x"+arg.hex()},"script_type":"lock"},"asc","0x5"])["objects"]
cell=[c for c in cells if int(c["output"]["capacity"],16)==100000*10**8][0]
in_txhash=cell["out_point"]["tx_hash"]; in_idx=int(cell["out_point"]["index"],16)
in_cap=int(cell["output"]["capacity"],16)
seal=H(in_txhash)  # the seal = the spent outpoint's tx hash (single-use)
commitment=ckbhash(b"ckb->cardano leap"+seal)   # the bound commitment, stored in the cell data
fee=100000  # 0.001 CKB
out_cap=in_cap-fee
# molecule Script (our lock), OutPoint, CellInput, CellOutput
def script_mol(code,htype,args): return table([code, bytes([htype]), molbytes(args)])
lock=script_mol(CODE,1,arg)
def outpoint(txh,idx): return H(txh)+u32(idx)
cell_input=u64(0)+outpoint(in_txhash,in_idx)                      # since=0
cell_output=table([u64(out_cap), lock, b''])                      # type=None
raw=table([u32(0), fixvec([outpoint(DEP_TX,0)+bytes([1])]), fixvec([]),
           fixvec([cell_input]), dynvec([cell_output]), dynvec([molbytes(commitment)])])
tx_hash=ckbhash(raw)
# signing message: tx_hash + (len||witness0) with lock zeroed to 65 bytes
wa_zero=table([molbytes(b'\x00'*65), b'', b''])
hasher=hashlib.blake2b(digest_size=32,person=b"ckb-default-hash")
hasher.update(tx_hash); hasher.update(u64(len(wa_zero))); hasher.update(wa_zero)
msg=hasher.digest()
sig=priv.sign_recoverable(msg, hasher=lambda x:x)                 # 65 bytes r||s||recid
wa=table([molbytes(sig), b'', b''])
tx={"version":"0x0",
    "cell_deps":[{"out_point":{"tx_hash":DEP_TX,"index":"0x0"},"dep_type":"dep_group"}],
    "header_deps":[],
    "inputs":[{"since":"0x0","previous_output":{"tx_hash":in_txhash,"index":hex(in_idx)}}],
    "outputs":[{"capacity":hex(out_cap),"lock":{"code_hash":"0x"+CODE.hex(),"hash_type":"type","args":"0x"+arg.hex()},"type":None}],
    "outputs_data":["0x"+commitment.hex()],
    "witnesses":["0x"+wa.hex()]}
txid=rpc("send_transaction",[tx])
print("CKB_LOCK_TXID", txid)
print("seal(outpoint tx):", in_txhash[:18], "commitment:", "0x"+commitment.hex()[:16])
json.dump({"ckb_lock_txid":txid,"seal_txhash":in_txhash,"commitment":"0x"+commitment.hex()}, open("/tmp/ckb_lock.json","w"))
