#!/usr/bin/env bash
cd /mnt/c/Users/telmo/chiral-study/spike/ckb-to-cardano
MINT=cbe5dbb65abc6efcf40842414883f8503ad2acf7bd31961b68fb74d55e623376
for i in $(seq 1 20); do
  code=$(curl -s -o /dev/null -w '%{http_code}' -H "project_id: $BLOCKFROST_PROJECT_ID" "https://cardano-preview.blockfrost.io/api/v0/txs/$MINT")
  if [ "$code" = "200" ]; then echo "mint confirmed at block"; break; fi
  echo "waiting for mint ($code)..."; sleep 12
done
python3.12 relayer/bg_native_burn.py burn 2>&1 | tail -8
