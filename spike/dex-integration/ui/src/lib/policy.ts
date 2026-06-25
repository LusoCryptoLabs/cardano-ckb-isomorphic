// policy.ts - decode the on-chain caps/pause policy cell, matching the CKB guard's `find_policy`:
// data = flags(1) ‖ min_amount(16 LE) ‖ max_amount(16 LE). flags bit0=global pause, bit1=pause-in,
// bit2=pause-out. max_amount==0 means "no cap". Used to surface limits + halt status in the UI and to
// pre-validate a leap amount client-side (the on-chain guard remains the authority).
import { decodeU128le } from "./amount";

export interface GuardPolicy {
  pausedGlobal: boolean;
  pausedIn: boolean;
  pausedOut: boolean;
  minAmount: bigint; // base units
  maxAmount: bigint; // base units, 0 = no cap
}

/** the implicit policy when none is deployed: open, no caps. */
export const OPEN_POLICY: GuardPolicy = {
  pausedGlobal: false,
  pausedIn: false,
  pausedOut: false,
  minAmount: 0n,
  maxAmount: 0n,
};

export function decodePolicy(data: Uint8Array): GuardPolicy {
  if (data.length < 33) throw new Error("policy cell data too short (need flags + min + max = 33 bytes)");
  const f = data[0];
  return {
    pausedGlobal: (f & 1) !== 0,
    pausedIn: (f & 2) !== 0,
    pausedOut: (f & 4) !== 0,
    minAmount: decodeU128le(data.slice(1, 17)),
    maxAmount: decodeU128le(data.slice(17, 33)),
  };
}

export type Direction = "in" | "out";

/** mirror of leap-guard-core::enforce_policy - client-side pre-check. Returns null if ok, else a reason. */
export function checkPolicy(p: GuardPolicy, dir: Direction, amount: bigint): string | null {
  if (p.pausedGlobal) return "Bridge is paused (global halt).";
  if (dir === "in" && p.pausedIn) return "Leap-in (mint) is paused.";
  if (dir === "out" && p.pausedOut) return "Leap-out (burn) is paused.";
  if (amount < p.minAmount) return `Below the minimum per-leap amount.`;
  if (p.maxAmount !== 0n && amount > p.maxAmount) return `Exceeds the per-leap cap.`;
  return null;
}
