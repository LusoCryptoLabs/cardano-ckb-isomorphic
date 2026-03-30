import fs from "node:fs";
const tW = "0x"+fs.readFileSync("/tmp/t_witness.hex","utf8").trim().replace(/^0x/,"");
const tRoot = fs.readFileSync("/tmp/t_root.hex","utf8").trim().replace(/^0x/,"");
const sealTxid = "a98b6636b3f08670cf0fe64a6176b64094d5929165ec62eb2944ac66b0f74da7";
const idx = "00000000";
const S1 = Buffer.from("bound-asset:demo:v2 owner=bob","utf8").toString("hex");
const t_out = "0x"+sealTxid+idx+S1;
const t_checkpoint = "0x"+"4c434b50"+tRoot; // "LCKP"||root
const out = { t_witness: tW.startsWith("0x")?tW:("0x"+tW.replace(/^0x/,"")), t_out, t_checkpoint, t_root: "0x"+tRoot };
out.t_witness = "0x"+fs.readFileSync("/tmp/t_witness.hex","utf8").trim().replace(/^0x/,"");
fs.writeFileSync("./p1t_hex.json", JSON.stringify(out));
console.log(JSON.stringify({t_out, t_checkpoint, t_witness_len:(out.t_witness.length-2)/2}, null, 2));
