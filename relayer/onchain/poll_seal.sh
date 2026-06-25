#!/bin/bash
# poll the Mithril aggregator until the seal mint tx is certified, then exit 0 (one notification).
cd /mnt/c/Users/telmo/chiral-study/relayer/onchain
i=0
while [ $i -lt 150 ]; do
  if python3 seal_cert_check.py; then echo SEAL_CERTIFIED; exit 0; fi
  i=$((i + 1))
  sleep 60
done
echo TIMEOUT
exit 1
