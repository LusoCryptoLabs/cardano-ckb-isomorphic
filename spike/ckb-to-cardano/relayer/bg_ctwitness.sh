#!/usr/bin/env bash
set -e
BURN=26a5228f127ac444d531752ff1d170648054da0cc65d5760cec5595376b31cee
AGG="https://aggregator.testing-preview.api.mithril.network/aggregator"
python3.12 - "$AGG" "$BURN" <<'PY' > /tmp/ct_rh.txt
import urllib.request,json,sys
AGG,BURN=sys.argv[1],sys.argv[2]
d=json.load(urllib.request.urlopen(f"{AGG}/proof/cardano-transaction?transaction_hashes={BURN}",timeout=25))
c=json.load(urllib.request.urlopen(f"{AGG}/certificate/{d['certificate_hash']}",timeout=25))
open("/root/ct_burn.json","w").write(json.dumps(c))
pm=c["protocol_message"]["message_parts"]
print(pm["cardano_transactions_merkle_root"], pm["latest_block_number"])
PY
/root/mv/target/release/transcode_witness /root/ct_burn.json >/dev/null
read ROOT HEIGHT < /tmp/ct_rh.txt
python3.12 - "$ROOT" "$HEIGHT" <<'PY'
import json,sys
root,height=sys.argv[1],int(sys.argv[2])
w=open("/tmp/cert_witness.bin","rb").read().hex()
json.dump({"root":"0x"+root,"height":height,"witHex":"0x"+w}, open("/mnt/c/Users/telmo/chiral-study/relayer/onchain/bg_ctwit.json","w"))
print("MWIT cert witness: root 0x"+root[:16]+".. height",height,"witbytes",len(w)//2)
PY
