import { useCallback, useEffect, useState } from "react";
import { useCcc } from "@ckb-ccc/connector-react";
import { TOKEN, CKB, CARDANO, ckbConfigured, policyConfigured, cardanoConfigured } from "./config";
import { fromBaseUnits } from "./lib/amount";
import { GuardPolicy, Direction } from "./lib/policy";
import { xudtBalance, readPolicy, xudtType, XudtBalance } from "./ckb/balances";
import { buildLeapBurn } from "./ckb/submit";
import { listWallets, connect, ftBalance, recipientCredentialHex, Cip30Api, CardanoBalance } from "./cardano/cip30";
import { BalanceCard } from "./components/BalanceCard";
import { PolicyBanner } from "./components/PolicyBanner";
import { LeapForm } from "./components/LeapForm";

const CKB_DECIMALS = 8; // CKB capacity is in shannons (1 CKB = 1e8)
const fmtCkb = (shannons: bigint) => fromBaseUnits(shannons, CKB_DECIMALS);

export function App() {
  const { open, disconnect, client, wallet, signerInfo } = useCcc();
  const signer = signerInfo?.signer;

  const [ckbAddr, setCkbAddr] = useState<string | null>(null);
  const [xudt, setXudt] = useState<XudtBalance | null>(null);
  const [policy, setPolicy] = useState<GuardPolicy | null>(null);

  const [cardanoWallets, setCardanoWallets] = useState<{ key: string; name: string; icon: string }[]>([]);
  const [cardanoApi, setCardanoApi] = useState<Cip30Api | null>(null);
  const [cardanoBal, setCardanoBal] = useState<CardanoBalance | null>(null);
  const [cardanoCred, setCardanoCred] = useState<string | null>(null);

  const [msg, setMsg] = useState<string | null>(null);

  useEffect(() => setCardanoWallets(listWallets()), []);

  // ---- CKB: resolve the account lock + read balances/policy when a signer connects ----
  const refreshCkb = useCallback(async () => {
    if (!signer) {
      setCkbAddr(null); setXudt(null);
      return;
    }
    const addr = await signer.getRecommendedAddressObj();
    setCkbAddr(addr.toString());
    if (ckbConfigured()) {
      try { setXudt(await xudtBalance(client, addr.script)); }
      catch (e) { setMsg(`CKB balance read failed: ${(e as Error).message}`); }
    }
    if (policyConfigured()) {
      try { setPolicy(await readPolicy(client)); }
      catch (e) { setMsg(`policy read failed: ${(e as Error).message}`); }
    }
  }, [signer, client]);

  useEffect(() => { void refreshCkb(); }, [refreshCkb]);

  // ---- Cardano: CIP-30 connect + FT balance + recipient credential ----
  const connectCardano = useCallback(async (key: string) => {
    try {
      const api = await connect(key);
      setCardanoApi(api);
      setCardanoCred(await recipientCredentialHex(api));
      if (cardanoConfigured()) setCardanoBal(await ftBalance(api));
    } catch (e) {
      setMsg(`Cardano connect failed: ${(e as Error).message}`);
    }
  }, []);

  const onLeap = useCallback(async (dir: Direction, base: bigint) => {
    const human = `${fromBaseUnits(base)} ${TOKEN.symbol}`;
    // Leap-IN (mint to CKB) is RELAYER-driven: the user initiates on the source chain, the relayer proves it
    // and mints here. Leap-OUT (burn on CKB) is user-initiated: we assemble the real burn tx from the user's
    // live xUDT cells. Broadcasting it additionally needs the deployed bridge owner cell-dep + the relayer
    // release (deploy step), so we assemble + report rather than send an incomplete tx.
    if (dir === "in") {
      setMsg(`Leap-in: initiate on the source chain; the relayer proves it and mints ${human} to ` +
        `${ckbAddr ?? "your JoyID lock"}. The guard enforces minted == verified-leap amount.`);
      return;
    }
    if (!signer || !ckbConfigured()) {
      setMsg(`Leap-out prepared: burn ${human} (${base} base units). Connect JoyID + set the deployed config to assemble it.`);
      return;
    }
    try {
      const lock = (await signer.getRecommendedAddressObj()).script;
      const tx = await buildLeapBurn(client, xudtType(), lock, base);
      if (!tx) { setMsg(`Insufficient ${TOKEN.symbol}: you hold less than ${human}.`); return; }
      setMsg(`Leap-out: ${human} across ${tx.inputs.length} xUDT input(s). The relayer assembles the complete ` +
        `FINALIZE tx (bound-cell consume + checkpoint proof + owner cell - see relayer/ckb_leap.mjs); you sign it with JoyID.`);
    } catch (e) {
      setMsg(`Leap-out assembly failed: ${(e as Error).message}`);
    }
  }, [ckbAddr, signer, client]);

  const ckbReady = !!signer && ckbConfigured();

  return (
    <div className="app">
      <header>
        <h1>{TOKEN.name} <span className="ticker">{TOKEN.symbol}</span></h1>
        <p className="tagline">
          Bridged via the isomorphic Cardano⇄CKB bridge · visible in JoyID (CKB xUDT) and Cardano wallets (CIP-68)
        </p>
      </header>

      <PolicyBanner policy={policy} configured={policyConfigured()} />

      <section className="cards">
        {/* ---- CKB / JoyID ---- */}
        <BalanceCard
          chain={`CKB · ${CKB.network}`}
          symbol={TOKEN.symbol}
          token={xudt ? fromBaseUnits(xudt.token) : null}
          status={signer ? (wallet?.name ?? "connected") : "not connected"}
          sub={
            xudt ? (
              <>
                {/* the financial-app UX rule: show CKB reserved, not just a bare token balance */}
                + <strong>{fmtCkb(xudt.ckbReserved)}</strong> CKB reserved across {xudt.cellCount} cell(s)
                <div className="addr">{ckbAddr}</div>
              </>
            ) : ckbConfigured() ? (
              "connect JoyID to read your balance"
            ) : (
              "set CKB.xudtCodeHash / bridgeLockHash in config.ts"
            )
          }
        >
          {signer ? (
            <button onClick={() => disconnect()}>Disconnect</button>
          ) : (
            <button className="primary" onClick={() => open()}>Connect JoyID / CKB</button>
          )}
          {signer && <button onClick={() => void refreshCkb()}>Refresh</button>}
        </BalanceCard>

        {/* ---- Cardano ---- */}
        <BalanceCard
          chain={`Cardano · ${CARDANO.network}`}
          symbol={TOKEN.symbol}
          token={cardanoBal ? fromBaseUnits(cardanoBal.ft) : null}
          status={cardanoApi ? "connected" : "not connected"}
          sub={
            cardanoApi ? (
              <>
                {cardanoBal && <>+ <strong>{fromBaseUnits(cardanoBal.lovelace, 6)}</strong> ₳</>}
                {cardanoCred && <div className="addr">cred {cardanoCred.slice(0, 12)}…</div>}
                {!cardanoConfigured() && <div className="dim">set CARDANO.policyId to read the FT balance</div>}
              </>
            ) : cardanoWallets.length ? (
              "choose a wallet"
            ) : (
              "no CIP-30 wallet detected (install Eternl/Lace)"
            )
          }
        >
          {!cardanoApi &&
            cardanoWallets.map((w) => (
              <button key={w.key} className="primary" onClick={() => void connectCardano(w.key)}>
                Connect {w.name}
              </button>
            ))}
          {cardanoApi && <button onClick={() => { setCardanoApi(null); setCardanoBal(null); setCardanoCred(null); }}>Disconnect</button>}
        </BalanceCard>
      </section>

      <section className="panel">
        <h2>Leap</h2>
        <LeapForm policy={policy} canSubmit={ckbReady} onSubmit={onLeap} />
      </section>

      {msg && <div className="toast" onClick={() => setMsg(null)}>{msg}</div>}

      <footer>
        <p>
          Amounts follow <code>guard/MAPPING_SPEC.md</code>: u128 base units, 16-byte LE, decimals are
          display-only. Caps/pause + conservation are enforced on-chain by the leap-mint guard.
        </p>
      </footer>
    </div>
  );
}
