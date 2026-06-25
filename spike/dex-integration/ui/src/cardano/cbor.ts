// cbor.ts - a minimal CBOR decoder, just enough to read a CIP-30 wallet's `getBalance()` Value
// (RFC 8949 major types 0-6). A Cardano Value is `coin | [coin, multiasset]` where multiasset is
// map(policy_id_bytes -> map(asset_name_bytes -> quantity)). We decode that to pull out the FT balance.
// Kept dependency-free and unit-tested so the Cardano read is real without pulling a serialization lib.

export type Cbor =
  | bigint
  | Uint8Array
  | string
  | Cbor[]
  | Map<Cbor, Cbor>
  | { tag: number; value: Cbor }
  | boolean
  | null;

class Reader {
  constructor(public buf: Uint8Array, public pos = 0) {}
  u8(): number {
    if (this.pos >= this.buf.length) throw new Error("cbor: unexpected end");
    return this.buf[this.pos++];
  }
  bytes(n: number): Uint8Array {
    if (this.pos + n > this.buf.length) throw new Error("cbor: unexpected end");
    const b = this.buf.slice(this.pos, this.pos + n);
    this.pos += n;
    return b;
  }
}

function readArg(r: Reader, info: number): number | bigint {
  if (info < 24) return info;
  if (info === 24) return r.u8();
  if (info === 25) return (r.u8() << 8) | r.u8();
  if (info === 26) return (BigInt(r.u8()) << 24n) | (BigInt(r.u8()) << 16n) | (BigInt(r.u8()) << 8n) | BigInt(r.u8());
  if (info === 27) {
    let v = 0n;
    for (let i = 0; i < 8; i++) v = (v << 8n) | BigInt(r.u8());
    return v;
  }
  throw new Error(`cbor: unsupported arg info ${info}`);
}

function decodeItem(r: Reader): Cbor {
  const ib = r.u8();
  const major = ib >> 5;
  const info = ib & 0x1f;
  switch (major) {
    case 0:
      return BigInt(readArg(r, info)); // unsigned int
    case 1:
      return -1n - BigInt(readArg(r, info)); // negative int
    case 2:
      return r.bytes(Number(readArg(r, info))); // byte string
    case 3:
      return new TextDecoder().decode(r.bytes(Number(readArg(r, info)))); // text
    case 4: {
      const n = Number(readArg(r, info));
      const arr: Cbor[] = [];
      for (let i = 0; i < n; i++) arr.push(decodeItem(r));
      return arr;
    }
    case 5: {
      const n = Number(readArg(r, info));
      const m = new Map<Cbor, Cbor>();
      for (let i = 0; i < n; i++) {
        const k = decodeItem(r);
        m.set(k, decodeItem(r));
      }
      return m;
    }
    case 6:
      return { tag: Number(readArg(r, info)), value: decodeItem(r) }; // tag
    case 7:
      if (info === 20) return false;
      if (info === 21) return true;
      if (info === 22) return null;
      throw new Error(`cbor: unsupported simple ${info}`);
    default:
      throw new Error(`cbor: unsupported major ${major}`);
  }
}

export function decodeCbor(bytes: Uint8Array): Cbor {
  return decodeItem(new Reader(bytes));
}

const toHex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

export interface DecodedValue {
  lovelace: bigint;
  /** quantity keyed by `${policyIdHex}${assetNameHex}` (the CIP-30 unit format). */
  assets: Map<string, bigint>;
}

/** Decode a CIP-30 Value (CBOR). Handles both the bare-coin and [coin, multiasset] forms. */
export function decodeValue(cborHex: string): DecodedValue {
  const clean = cborHex.replace(/^0x/, "");
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  const v = decodeCbor(bytes);
  const assets = new Map<string, bigint>();
  if (typeof v === "bigint") return { lovelace: v, assets };
  if (!Array.isArray(v)) throw new Error("cbor: unexpected Value shape");
  const lovelace = v[0] as bigint;
  const ma = v[1];
  if (ma instanceof Map) {
    for (const [pid, names] of ma.entries()) {
      if (!(pid instanceof Uint8Array) || !(names instanceof Map)) continue;
      for (const [name, qty] of names.entries()) {
        if (!(name instanceof Uint8Array)) continue;
        assets.set(toHex(pid) + toHex(name), qty as bigint);
      }
    }
  }
  return { lovelace, assets };
}
