"""cardano_status.py - emit a compact JSON health snapshot of the preview side for the leap orchestrator:
wallet tADA, utxo + collateral counts, and the current seal outpoint at binding_lock. Keyless (Koios)."""
import json, os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import cardano_net, pycardano as pc

def main():
    inst = json.load(open(os.path.join(HERE, "..", "deployed", "cardano", "preview", "seal-instance-ours.json")))
    ctx = cardano_net.chain_context()
    sk, vk, addr = cardano_net.account("coordinator")
    us = ctx.utxos(str(addr))
    pol = pc.ScriptHash(bytes.fromhex(inst["seal_policy"]))
    ls = ctx.utxos(inst["binding_lock_addr"])
    seal = next((str(u.input.transaction_id) + "#" + str(u.input.index)
                 for u in ls if u.output.amount.multi_asset and pol in u.output.amount.multi_asset.data), None)
    print(json.dumps({
        "tada": sum(int(u.output.amount.coin) for u in us) // 1_000_000,
        "nUtxo": len(us),
        "collateral": sum(1 for u in us if not u.output.amount.multi_asset and int(u.output.amount.coin) >= 5_000_000),
        "seal": seal,
    }))

if __name__ == "__main__":
    main()
