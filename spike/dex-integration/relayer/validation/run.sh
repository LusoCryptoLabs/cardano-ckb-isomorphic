#!/usr/bin/env bash
# #3 validation: run the relayer's FINALIZE witness through the real bound_asset_unified verifier.
# Usage: ./run.sh            (uses the deployed verifier fetched from Pudge - recommended)
set -euo pipefail
cd "$(dirname "$0")"
DS=/tmp/ds.json
MOCK=/tmp/finalize_mock.json
VBIN=${VBIN:-/tmp/deployed_bound_asset.bin}

echo "==> 1. generate the self-consistent FINALIZE dataset"
( cd gen && cargo run --release --quiet ) > "$DS"

echo "==> 2. cross-check: relayer JS encoder == reference witness (byte-identical)"
node --input-type=module -e '
import { encodeFinalizeWitness } from "../mithril_proof.mjs";
import { readFileSync } from "node:fs";
const ds = JSON.parse(readFileSync(process.env.DS,"utf8")), c = ds.components;
const w = encodeFinalizeWitness({ txBody: ds.tx_body, subRoot: c.sub_root, subPos: BigInt(c.sub_pos),
  subSize: BigInt(c.sub_size), subItems: c.sub_items, rangeKey: c.range_key, masterPos: BigInt(c.master_pos),
  masterSize: BigInt(c.master_size), masterItems: c.master_items });
const hex = Array.from(w,b=>b.toString(16).padStart(2,"0")).join("");
if (hex !== ds.witness) { console.error("MISMATCH"); process.exit(1); }
console.log("   JS encoder == reference witness:", hex.length/2, "bytes");
' DS="$DS"

if [ ! -f "$VBIN" ]; then
  echo "==> fetch the deployed verifier (extract the ELF cell-dep from a live Pudge leap):"
  echo "    cd ../guard/integration && python3 replay_live_leap.py 0x0318d35f...e667 > /tmp/m.json"
  echo "    then pull mock_info.cell_deps[*] whose ckbhash(data)==0x42f74fbc... into $VBIN"
  exit 1
fi

echo "==> 3. assemble the FINALIZE mock-tx + 4. run the verifier in CKB-VM"
python3 assemble.py "$DS" "$VBIN" > "$MOCK"
ckb-debugger --tx-file "$MOCK" --cell-type input --cell-index 0 --script-group-type type
echo "(code 4/5 = MMR proof rejected; reaching a higher code = witness parsed + both MMR proofs verified)"
