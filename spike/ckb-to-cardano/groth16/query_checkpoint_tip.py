#!/usr/bin/env python3
"""Print the current on-chain checkpoint tip_height (by the manifest's checkpoint_nft at the advance addr)."""
import sys, os, json
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, "..", "..", ".."))
sys.path.insert(0, HERE); sys.path.insert(0, os.path.join(ROOT, "cardano", "binding"))
import cbor2, pycardano as pc, cardano_net
CKBC = json.load(open(os.path.join(ROOT, "deployed", "cardano", "preview", "ckbcert-genesis.json")))
ctx = cardano_net.chain_context()
addr = pc.Address(payment_part=pc.ScriptHash(bytes.fromhex(CKBC["advance_ckbcert_script"])), network=pc.Network.TESTNET)
nft = pc.ScriptHash(bytes.fromhex(CKBC["checkpoint_nft"]))
for u in ctx.utxos(str(addr)):
    ma = u.output.amount.multi_asset
    if ma and nft in ma:
        d = u.output.datum
        raw = d.to_cbor() if hasattr(d, "to_cbor") else (d.cbor if hasattr(d, "cbor") else bytes(d))
        print(int(cbor2.loads(raw).value[3]))
        sys.exit(0)
print("NONE"); sys.exit(1)
