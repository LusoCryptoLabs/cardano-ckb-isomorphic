# The leap, executed on live testnets (real, explorer-visible)

A complete CKB→Cardano asset leap, end to end, with the ZK verification of CKB consensus executing in a
**real Cardano transaction**. Keys were generated locally (`relayer/genkeys.py`) and faucet-funded.

## The coherent leap (Cardano verifies THIS specific CKB lock)
1. **CKB lock (Pudge)** — `0x4923241abfd204a1aff2099b4cc0f2536d425d19936b54616f3a5263d4691bcb`
   - in block **21,344,511**; spends the single-use **seal** outpoint
     `0x5d052540d3d26e706ac741ddab1e4cd2463249e9d55099a82a8876fabdf1e47c:0`; writes the bound commitment.
   - https://pudge.explorer.nervos.org/transaction/0x4923241abfd204a1aff2099b4cc0f2536d425d19936b54616f3a5263d4691bcb
2. **Relayer proof** — `relayer.py` + `relay_prove` proved that lock tx's inclusion: R1 PoW of block
   21,344,511 + R2 ChainRootMMR membership + R3 CBMT tx-inclusion + R4 seal/commitment.
   `arkworks verify = true`, 1,230,156 constraints. Public inputs bind chain_root, the seal above, and the commitment.
3. **Cardano lock (preview)** — `6407614538c94666243b5b5d8a53c4178cd731a9cf2092dec3dd9c627291cf29`
   (ADA locked behind the verifier; datum = the Groth16 vk + the proof's public inputs).
   - https://preview.cardanoscan.io/transaction/6407614538c94666243b5b5d8a53c4178cd731a9cf2092dec3dd9c627291cf29
4. **Cardano verify (preview)** — `f99c3461c77a812287a79d7fb5ee60b0dc83364853018a0e42a18b788805892b`
   - the spend runs `verify(vk, proof, public_inputs)` ON-CHAIN: **cpu 2,727,805,423 / mem 67,442** (a false
     proof would abort the script). This is Cardano cryptographically verifying CKB's Eaglesong-PoW consensus.
   - https://preview.cardanoscan.io/transaction/f99c3461c77a812287a79d7fb5ee60b0dc83364853018a0e42a18b788805892b

## First standalone on-chain verify (earlier block 21,343,874)
- Cardano lock `bfdfae0a9c64ef4205d3cb0f77d9b6780623d83d524488ce66483215bb6db916`,
  verify `6a43b3eaf6a326028a438c1061ad2d7a68168e3d974b5df9f14c1368272a650d` (cpu 2,727,805,423).

## The minted bridged asset (now visible on Cardano)
5. **Mint (preview)** — `21ad4a44c8385c9940f4f9b484d23e5b7ffef5a7e432c09951fab166a37d453e`
   - minting policy `zk_chiral_mint` mints **100,000 ckCKB** ONLY because the same Groth16 proof verifies
     on-chain in the mint (a false proof => no token). Policy id `8f11f2b176c143f1aaba0e48662052b0b8c3830161c73194eb60df2a`.
   - asset unit: `8f11f2b176c143f1aaba0e48662052b0b8c3830161c73194eb60df2a636b434b42` ("ckCKB"); held by our wallet.
   - token:   https://preview.cardanoscan.io/token/8f11f2b176c143f1aaba0e48662052b0b8c3830161c73194eb60df2a636b434b42
   - mint tx: https://preview.cardanoscan.io/transaction/21ad4a44c8385c9940f4f9b484d23e5b7ffef5a7e432c09951fab166a37d453e
   - wallet:  https://preview.cardanoscan.io/address/addr_test1vqk7v3nm48ac2ygxqm44mn2jpf3nmqc33eakn3j44pxjvfsv5rqhu
   (quantity 100,000 mirrors the locked CKB. AMOUNT/NAME BINDING NOW ENFORCED in zk_chiral_mint.ak: the mint
   policy requires minted qty == the amount committed in the CKB-bound state and the name pinned to the
   commitment public input — validator-level, aiken-tested; relayer wiring + redeploy is the integration step.)

## Reverse leg — round trip closed (burn on Cardano -> unlock on CKB)
6. **Burn (preview)** — `6608c4c828ceec5bb94c0973aeb41f5e04a85225a06edd90874b09d20515a800`
   - burns 100,000 ckCKB; on-chain supply -> **0** (mint/burn ops = 2). The bridged asset leaves Cardano.
   - https://preview.cardanoscan.io/transaction/6608c4c828ceec5bb94c0973aeb41f5e04a85225a06edd90874b09d20515a800
7. **CKB unlock (Pudge)** — `0xde70a26d5254d653f0a03e870ecf5eec971d75952803462201e6af5df6062d2d`
   - spends the bound cell, clears the commitment data -> the CKB asset is free again.
   - https://pudge.explorer.nervos.org/transaction/0xde70a26d5254d653f0a03e870ecf5eec971d75952803462201e6af5df6062d2d
   - NOTE: this demo unlock was authorized by our key. BURN-GATED UNLOCK NOW BUILT + DEPLOYED LIVE on
     Pudge (spike/burn-gated-unlock/, codeHash 0x7d251a83..): a CKB lock script that releases the locked
     CKB ONLY on a Mithril-certified Cardano burn — it reads the certified tx-set root from a checkpoint
     cellDep and verifies the burn 6608c4c8 MKMapProof in-VM. Demonstrated: lock 0x3e4b81a5 -> UNLOCK
     0xefb60dfce.. (block 21,358,984, cell spent); and a spend WITHOUT the proof is rejected (lock error
     code 10). So conservation on the return path is now gated by the certified burn, not a key.

## Conservation across the full round trip (the asset is never live on both at once)
| stage            | CKB asset            | Cardano ckCKB supply |
|------------------|----------------------|----------------------|
| start            | free (300k CKB)      | 0                    |
| after forward    | LOCKED (bound cell)  | 100,000 (minted)     |
| after reverse    | FREE (unlocked)      | 0 (burned)           |
Locked-on-CKB <=> minted-on-Cardano; burned-on-Cardano <=> unlocked-on-CKB. Total conserved; one side active at a time.

## Addresses (testnet)
- CKB Pudge: `ckt1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsqfcfsm2sf0t0gfr774h6mgxwkxpedr4fdshwywks`
- Cardano preview: `addr_test1vqk7v3nm48ac2ygxqm44mn2jpf3nmqc33eakn3j44pxjvfsv5rqhu`
- Verifier script (preview): `addr_test1wqnfuvusap6300a0gytx4q0ttgmmyyadwrrcztfzl5pvlnqd3k77x` (hash 269e3390…)

## Conservation (why it isn't double-spent)
The asset is locked on CKB (consumed there) and the Cardano side mints/releases only against a proof that
the lock is in a real, PoW-worked CKB chain, binding the single-use seal. The seal can be spent once on CKB,
so the proof can mint once on Cardano; the reverse (burn on Cardano → unlock on CKB) returns it. Locked-on-CKB
⇔ active-on-Cardano: never both. Tooling: `relayer/ckb_lock.py` (CKB lock), `relayer/cardano_leap.py`
(lock+verify), `validators/zk_leap_lock.ak` (the on-chain verifier-lock).
