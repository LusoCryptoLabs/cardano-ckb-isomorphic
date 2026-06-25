#!/usr/bin/env python3
"""Generate testnet keys/addresses for both legs (deps: coincurve, pynacl).
  CKB Pudge: secp256k1_blake160 lock, full bech32m 'ckt' address (RFC0021).
  Cardano preview: Ed25519 enterprise address, bech32 'addr_test' (header 0x60).
Writes private keys to the path given (default /tmp) - DO NOT COMMIT THEM."""
import coincurve, nacl.signing, hashlib, os, json, sys
CH="qpzry9x8gf2tvdw0s3jn54khce6mua7l"
def _pm(v):
    G=[0x3b6a57b2,0x26508e6d,0x1ea119fa,0x3d4233dd,0x2a1462b3];c=1
    for x in v:
        b=c>>25;c=((c&0x1ffffff)<<5)^x
        for i in range(5): c^=G[i] if ((b>>i)&1) else 0
    return c
def _hx(h): return [ord(x)>>5 for x in h]+[0]+[ord(x)&31 for x in h]
def enc(hrp,data,const):  # const=1 bech32, 0x2bc830a3 bech32m
    pm=_pm(_hx(hrp)+data+[0]*6)^const
    return hrp+'1'+''.join(CH[d] for d in data+[(pm>>5*(5-i))&31 for i in range(6)])
def bits(d,f,t,pad=True):
    a=0;n=0;r=[];m=(1<<t)-1
    for b in d:
        a=(a<<f)|b;n+=f
        while n>=t: n-=t;r.append((a>>n)&m)
    if pad and n: r.append((a<<(t-n))&m)
    return r
def ckbhash(b): return hashlib.blake2b(b,digest_size=32,person=b"ckb-default-hash").digest()
out=sys.argv[1] if len(sys.argv)>1 else "/tmp"
# CKB
priv=os.urandom(32); pub=coincurve.PrivateKey(priv).public_key.format(compressed=True)
arg=ckbhash(pub)[:20]
CODE=bytes.fromhex("9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8")
ckb_addr=enc("ckt",bits(list(bytes([0])+CODE+bytes([1])+arg),8,5),0x2bc830a3)
json.dump({"priv_hex":priv.hex(),"lock_arg":arg.hex(),"address":ckb_addr},open(f"{out}/ckb_key.json","w"))
# Cardano
sk=nacl.signing.SigningKey.generate(); kh=hashlib.blake2b(bytes(sk.verify_key),digest_size=28).digest()
ada_addr=enc("addr_test",bits(list(bytes([0x60])+kh),8,5),1)
json.dump({"sk_hex":bytes(sk).hex(),"key_hash":kh.hex(),"address":ada_addr},open(f"{out}/cardano_key.json","w"))
print("CKB Pudge :",ckb_addr)
print("Cardano   :",ada_addr)
