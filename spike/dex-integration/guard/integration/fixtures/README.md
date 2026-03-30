# Real on-chain binaries (fetched from CKB Pudge testnet)

These are the **actual deployed** type-script binaries, pulled from Pudge so the integration tests run the
real scripts (not stand-ins). Provenance — fetch with `get_transaction(tx_hash).outputs_data[index]` via
`https://testnet.ckb.dev`:

| file | code hash (testnet) | code cell out-point | bytes |
|---|---|---|---|
| `xudt_testnet.bin` | `0x25c29dc317811a6f6f3985a7a9ebc4838bd388d19d0feeecf0bcd60f6c0975bb` | `0xbf6fb538763efec2a70a6a3dcb7242787087e1030c4e7d86585bc63a9d337f5f:0` | 33696 |
| `unique_testnet.bin` | `0x8e341bcfec6393dcd41e635733ff2dca00a6af546949f70c57a706c0f344df8b` | `0xff91b063c78ed06f10a1ed436122bd7d671f9a72ef5f5fa28d05252c17cf4cef:0` | 29528 |

Both are RISC-V ELF (machine 243). Out-points/code-hashes are the CCC `KnownScript.XUdt` / `UniqueType`
testnet config. Re-fetch any time; the tests reference them by data hash, so a re-fetch of the same cell
yields identical bytes.
