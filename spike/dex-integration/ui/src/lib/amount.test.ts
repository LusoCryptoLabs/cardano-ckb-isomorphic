// amount.test.ts - pins the UI's value encoding to the SAME vectors as leap-guard-core (Rust) and
// leap_guard.ak (Cardano), so all three agree byte-for-byte. Run: pnpm test.
import { describe, it, expect } from "vitest";
import { toBaseUnits, fromBaseUnits, u128le, decodeU128le, bytesToHex } from "./amount";
import { decodePolicy, checkPolicy } from "./policy";

describe("amount encoding (MAPPING_SPEC)", () => {
  it("toBaseUnits @6dp", () => {
    expect(toBaseUnits("52.5", 6)).toBe(52_500_000n);
    expect(toBaseUnits("0", 6)).toBe(0n);
    expect(toBaseUnits("52", 6)).toBe(52_000_000n);
  });
  it("rejects floats / excess precision / negatives", () => {
    expect(() => toBaseUnits("1.2.3", 6)).toThrow();
    expect(() => toBaseUnits("1.1234567", 6)).toThrow();
    expect(() => toBaseUnits("-1", 6)).toThrow();
    expect(() => toBaseUnits("abc", 6)).toThrow();
  });
  it("fromBaseUnits round-trips display", () => {
    expect(fromBaseUnits(52_500_000n, 6)).toBe("52.5");
    expect(fromBaseUnits(52_000_000n, 6)).toBe("52");
  });
  it("u128le is little-endian canonical (matches encode_amount_le)", () => {
    expect(bytesToHex(u128le(1n))).toBe("01000000000000000000000000000000");
    expect(bytesToHex(u128le(256n))).toBe("00010000000000000000000000000000");
  });
  it("decode round-trips, including from a longer state prefix", () => {
    for (const a of [0n, 1n, 52_000_000n, (1n << 64n) - 1n, (1n << 128n) - 1n]) {
      expect(decodeU128le(u128le(a))).toBe(a);
    }
    const state = new Uint8Array([...u128le(52_000_000n), ...new Uint8Array(32).fill(7)]);
    expect(decodeU128le(state)).toBe(52_000_000n);
  });
});

describe("policy decode + check (matches the on-chain guard)", () => {
  const mk = (flags: number, min: bigint, max: bigint) =>
    new Uint8Array([flags, ...u128le(min), ...u128le(max)]);
  it("decodes flags + caps", () => {
    const p = decodePolicy(mk(0b101, 1000n, 100_000_000n));
    expect(p.pausedGlobal).toBe(true);
    expect(p.pausedIn).toBe(false);
    expect(p.pausedOut).toBe(true);
    expect(p.minAmount).toBe(1000n);
    expect(p.maxAmount).toBe(100_000_000n);
  });
  it("checkPolicy enforces caps + pause like enforce_policy", () => {
    const open = decodePolicy(mk(0, 0n, 0n));
    expect(checkPolicy(open, "in", 1n)).toBeNull();
    const capped = decodePolicy(mk(0, 1000n, 100_000_000n));
    expect(checkPolicy(capped, "in", 52_000_000n)).toBeNull();
    expect(checkPolicy(capped, "in", 100_000_001n)).not.toBeNull(); // over cap
    expect(checkPolicy(capped, "out", 999n)).not.toBeNull(); // under min
    const pausedIn = decodePolicy(mk(0b10, 0n, 0n));
    expect(checkPolicy(pausedIn, "in", 1n)).not.toBeNull();
    expect(checkPolicy(pausedIn, "out", 1n)).toBeNull(); // out still flows
  });
});
