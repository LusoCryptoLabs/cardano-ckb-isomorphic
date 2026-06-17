#!/usr/bin/env bash
D=/mnt/c/Users/telmo/chiral-study/relayer/onchain/chain
cp "$D/chain.json" "$D/chain.json.bak-1323" 2>/dev/null || true
cp /tmp/chain_pinned/chain.json "$D/chain.json"
cp /tmp/chain_pinned/witnesses/*.bin "$D/witnesses/"
echo "witnesses now: $(ls "$D/witnesses/" | tr '\n' ' ')"
python3 - "$D/chain.json" <<'PY'
import json,sys
m=json.load(open(sys.argv[1]))
print("advances:", len(m["advances"]), m["advances"][0]["from"], "->", m["advances"][-1]["to"])
od=m["deploy"]["out_data"]
print("deploy out_data:", od[:18], "len", (len(od)-2)//2, "bytes  height", m["deploy"].get("height"))
print("genesis 1319 ck:", m["epochs"]["1319"]["checkpoint"][:18])
PY
echo PROMOTE_DONE
