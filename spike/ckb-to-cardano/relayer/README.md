# CKB→Cardano relayer + broadcast runbook

Two stages, both runnable here against **live Pudge** (CKB testnet RPC is open):

1. **`relayer.py`** — fetch stage. Pulls the current tip, a confirmed block `T` with a real tx, its 3
   predecessors (checkpoint MMR), and the tx's canonical CBMT proof (`get_transaction_proof`). Emits
   `witness.json`. (Production swaps the 4-header MMR for the canonical light-client MMR proof.)
2. **`relay_prove`** (`circuit/prover`) — prove stage. Reads `witness.json`, recomputes the header hash
   from live bytes (asserted), derives the CBMT path + checkpoint MMR, builds the leap circuit
   (R1 PoW + R2 MMR-membership + R3 tx-inclusion + R4 seal/commitment), runs Groth16, and emits a
   **broadcast-ready Cardano redeemer** (`relayer_redeemer.example.json`): vk, proof, public inputs
   `(chain_root, seal, commitment)` — exactly what `cardano_bound.ak` verifies.

Run (verified live in this repo, block 21,343,874):
```
python3 relayer/relayer.py https://testnet.ckb.dev /tmp/witness.json
cargo run --release --bin relay_prove /tmp/witness.json > redeemer.json   # arkworks verify = true
```
The emitted proof is accepted on-chain by the Aiken verifier (`g16/live_relay_test.ak`, PASS).

## Broadcasting (the part this sandbox can't do — needs keys/funds)
- **CKB lock tx → Pudge:** the RPC accepts `send_transaction`, so broadcasting works *given a funded
  Pudge secp256k1 key*. Build the lock cell (the bound cell), sign, submit. (Not done here: no funded key.)
- **Cardano mint tx → preview:** needs a submit path — `cardano-cli`/Ogmios/Blockfrost — plus a funded
  preview key and the deployed `cardano_bound.ak` script. Blockfrost here returns 403 (no API key);
  `cardano-cli` isn't installed. So the Cardano leg can't be broadcast from this sandbox.

To do a real end-to-end leap (and get explorer links), provide: a funded **Pudge** key + a funded
**preview** key + a Cardano submit endpoint (Blockfrost project id or a local node). Then:
lock on Pudge → `relayer.py`+`relay_prove` → submit the Cardano mint with `redeemer.json` →
the reverse burn/unlock. That produces a CKB txid + a Cardano txid (the explorer-visible leap).

## Funding the keys (manual — faucets block scripted claims)
`python3 relayer/genkeys.py /tmp` generates valid testnet keys/addresses for both legs (verified:
the CKB address is accepted by the Pudge indexer; capacity 0 until funded). Both faucets require a human:
- **CKB Pudge:** https://faucet.nervos.org/ — sign in with GitHub, paste the `ckt1...` address (no API).
- **Cardano preview:** https://docs.cardano.org/cardano-testnets/tools/faucet — needs an API key/captcha;
  the `send-money` endpoint returns `InvalidApiKey` without one. Paste the `addr_test1...` address.

Once both are funded, the end-to-end leap is: build+sign+`send_transaction` the CKB lock cell on Pudge →
`relayer.py`+`relay_prove` → submit the Cardano mint with `redeemer.json` via a node/Ogmios/Blockfrost →
reverse burn/unlock. That yields the explorer-visible CKB + Cardano txids.
