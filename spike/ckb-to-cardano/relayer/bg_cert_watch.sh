#!/usr/bin/env bash
# Poll the Mithril preview aggregator until the burn tx is CERTIFIED (lands in a certified snapshot).
BURN=26a5228f127ac444d531752ff1d170648054da0cc65d5760cec5595376b31cee
AGG="https://aggregator.testing-preview.api.mithril.network/aggregator"
for i in $(seq 1 80); do
  resp=$(curl -s --max-time 25 "$AGG/proof/cardano-transaction?transaction_hashes=$BURN")
  if echo "$resp" | grep -q "\"certified_transactions\":\[\"$BURN\"\]"; then
    echo "CERTIFIED: $BURN"
    echo "$resp" | head -c 300; echo
    exit 0
  fi
  echo "not yet certified (poll $i)..."
  sleep 90
done
echo "TIMEOUT: still not certified after polling"
exit 1
