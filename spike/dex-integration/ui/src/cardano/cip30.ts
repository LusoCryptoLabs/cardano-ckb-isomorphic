// cip30.ts - real Cardano wallet connect via CIP-30 (Eternl/Lace/…), with NO backend: connect, read the
// bridged FT balance from the wallet's own `getBalance()` Value, and extract the recipient payment
// credential from the change address (the 28-byte credential the Cardano leap-mint guard binds to).
import { decodeValue } from "./cbor";
import { ftUnitHex } from "../config";

export interface Cip30Api {
  getBalance(): Promise<string>; // CBOR-hex Value
  getChangeAddress(): Promise<string>; // CBOR-hex address bytes
  getUsedAddresses(): Promise<string[]>;
  getNetworkId(): Promise<number>;
}
interface Cip30Wallet {
  name: string;
  icon: string;
  apiVersion: string;
  enable(): Promise<Cip30Api>;
  isEnabled(): Promise<boolean>;
}
type CardanoWindow = { cardano?: Record<string, Cip30Wallet> };

/** Injected CIP-30 wallets (key = the `window.cardano.<key>` handle). */
export function listWallets(): { key: string; name: string; icon: string }[] {
  const c = (window as unknown as CardanoWindow).cardano;
  if (!c) return [];
  return Object.entries(c)
    .filter(([, w]) => w && typeof w.enable === "function")
    .map(([key, w]) => ({ key, name: w.name ?? key, icon: w.icon ?? "" }));
}

export async function connect(key: string): Promise<Cip30Api> {
  const c = (window as unknown as CardanoWindow).cardano;
  if (!c || !c[key]) throw new Error(`wallet ${key} not found`);
  return c[key].enable();
}

export interface CardanoBalance {
  lovelace: bigint;
  ft: bigint; // base units of the bridged FT (policyId ++ (333)name)
}

export async function ftBalance(api: Cip30Api): Promise<CardanoBalance> {
  const value = decodeValue(await api.getBalance());
  return { lovelace: value.lovelace, ft: value.assets.get(ftUnitHex()) ?? 0n };
}

/** The 28-byte payment credential from the (Shelley) change address: header(1) ‖ payment_cred(28) ‖ … */
export async function recipientCredentialHex(api: Cip30Api): Promise<string> {
  const addrHex = (await api.getChangeAddress()).replace(/^0x/, "");
  if (addrHex.length < 2 + 56) throw new Error("unexpected address length");
  return addrHex.slice(2, 2 + 56); // skip header byte, take 28 bytes
}
