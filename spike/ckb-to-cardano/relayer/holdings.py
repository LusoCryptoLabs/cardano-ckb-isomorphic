import json, urllib.request
from pycardano import PaymentSigningKey, PaymentVerificationKey, Address, Network
# inline bech32 decode (BIP-173) - no external dep
CH = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
def bech32_decode(b):
    pos = b.rfind("1"); hrp = b[:pos]; data = [CH.find(c) for c in b[pos+1:]]
    return hrp, data[:-6]  # strip 6-char checksum
def convertbits(data, frm, to):
    acc=0; bits=0; out=[]
    for v in data:
        acc=(acc<<frm)|v; bits+=frm
        while bits>=to: bits-=to; out.append((acc>>bits)&((1<<to)-1))
    return bytes(out)
txt = open("/mnt/c/Users/telmo/.chiral/preview_relayer.key").read().strip()
hrp, data = bech32_decode(txt)
kb = convertbits(data, 5, 8)[:32]
sk = PaymentSigningKey.from_primitive(kb)
vk = PaymentVerificationKey.from_signing_key(sk)
addr = Address(payment_part=vk.hash(), network=Network.TESTNET)
print("hrp:", hrp, "| key bytes:", len(kb))
print("preview address:", str(addr))
json.dump({"sk_hex": kb.hex(), "key_hash": vk.hash().payload.hex(), "address": str(addr)}, open("/tmp/cardano_key.json","w"))
print("staged /tmp/cardano_key.json")
BF=__import__("os").environ.get("BLOCKFROST_PROJECT_ID",""); BASE="https://cardano-preview.blockfrost.io/api/v0"
def bf(p): return json.load(urllib.request.urlopen(urllib.request.Request(BASE+p, headers={"project_id":BF}), timeout=30))
try:
    for a in bf("/addresses/"+str(addr)).get("amount", []):
        u=a["unit"]
        if u=="lovelace": print(f"  ADA: {int(a['quantity'])/1e6:.2f}")
        else: print(f"  TOKEN policy={u[:56]} name_hex={u[56:]} qty={a['quantity']}")
except urllib.error.HTTPError as e:
    print("holdings:", e.code, "(404 = empty address)")
