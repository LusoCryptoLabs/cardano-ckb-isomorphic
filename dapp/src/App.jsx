import { useEffect, useState } from "react";
import { ccc } from "@ckb-ccc/connector-react";
import { listCardanoWallets, connectCardano, reconnectCardano, rememberedWallet, forgetCardano, shortHex } from "./cardano.js";
import { lockCkb, cardanoRecipientCred } from "./leap.js";
import { waitLockConfirmed, requestProof, mintChiCKB, burnChiCKB, requestRelease } from "./mint.js";
import { fetchXadaConfig, lockAda, requestXadaMint, requestXadaReturn, buildXadaBurn, submitXadaBurn } from "./xada.js";
import { useRelayLoad, useJobPosition, loadSummary } from "./queue.js";

const ckbClient = new ccc.ClientPublicTestnet();
const C = { fg: "#e7edf5", dim: "#95a1b4", mut: "#7c8ba1", blue: "#6b9bff", green: "#35d6a0", warn: "#d29922", bad: "#f85149", off: "#3a4456" };
const mono = "'IBM Plex Mono', ui-monospace, monospace";
const fmtCKB = (sh) => sh != null ? (Number(BigInt(sh)) / 1e8).toLocaleString(undefined, { maximumFractionDigits: 4 }) : "-";
const CKB_FAUCET = "https://faucet.nervos.org/";
const ADA_FAUCET = "https://docs.cardano.org/cardano-testnets/tools/faucet";
// free browser wallets a newcomer needs (one per chain)
const WALLETS = {
  ckb: [{ name: "JoyID", url: "https://joy.id/", note: "easiest - no extension" }, { name: "MetaMask", url: "https://metamask.io/", note: "+ Nervos snap" }],
  ada: [{ name: "Lace", url: "https://www.lace.io/", note: "official Cardano wallet" }, { name: "Eternl", url: "https://eternl.io/", note: "alternative" }],
};
// Donations: support continued R&D. A donation, NOT an investment - testnet tokens have no value. Set a real
// mainnet address / sponsor link to enable the Support panel (left null = panel hidden until provided).
const DONATE = {
  github: "https://github.com/LusoCryptoLabs",
  ada: null,   // e.g. "addr1..." (Cardano mainnet) - set to show a copy-able tip address
  btc: null,   // e.g. "bc1..."   (Bitcoin)        - set to show a copy-able tip address
};

// click-to-copy address (copies the FULL value, shows a short form)
function CopyAddr({ value, color = "#c4cedd" }) {
  const [done, setDone] = useState(false);
  const copy = () => { try { navigator.clipboard.writeText(value); setDone(true); setTimeout(() => setDone(false), 1200); } catch { /* no clipboard */ } };
  return (
    <div onClick={copy} title="click to copy full address" style={{ fontFamily: mono, fontSize: 12, color, wordBreak: "break-all", marginBottom: 6, cursor: "pointer", display: "flex", alignItems: "center", gap: 7 }}>
      {shortHex(value, 16, 10)}
      <span style={{ fontSize: 11, color: done ? C.green : "#5d6b80", flexShrink: 0 }}>{done ? "✓ copied" : "⧉ copy"}</span>
    </div>
  );
}
const faucetLink = (href, label) => <a href={href} target="_blank" rel="noopener" style={{ fontSize: 11, color: "#6f7d92", textDecoration: "none", display: "inline-block", marginTop: 8 }} className="lk">{label} ↗</a>;

// ---------- wallet cards (real ccc + CIP-30) ----------
function CkbCard() {
  const { open, disconnect, wallet } = ccc.useCcc();
  const signer = ccc.useSigner();
  const [addr, setAddr] = useState(null), [bal, setBal] = useState(null);
  useEffect(() => {
    let alive = true;
    (async () => {
      if (!signer) { setAddr(null); setBal(null); return; }
      try { const a = await signer.getRecommendedAddress(); if (alive) setAddr(a); const b = await signer.getBalance(); if (alive) setBal(b); } catch { /* ignore */ }
    })();
    return () => { alive = false; };
  }, [signer]);
  return (
    <div style={{ border: "1px solid #1f4435", borderTop: "2px solid " + C.green, borderRadius: 14, background: "#091310", padding: "18px 20px" }}>
      <div style={{ fontFamily: mono, fontSize: 10.5, letterSpacing: ".1em", color: "#5d8a78", textTransform: "uppercase", marginBottom: 8 }}>Nervos CKB · Pudge</div>
      <div style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 14, fontWeight: 600, marginBottom: 12 }}>
        <span style={{ width: 8, height: 8, borderRadius: "50%", background: signer ? C.green : C.off }} />
        {signer ? (wallet?.name || "Connected") : "Wallet"}
      </div>
      {signer ? (
        <>
          {addr ? <CopyAddr value={addr} /> : <div style={{ fontFamily: mono, fontSize: 12, color: "#c4cedd", marginBottom: 6 }}>…</div>}
          <div style={{ fontSize: 20, fontWeight: 700 }}>{bal != null ? (Number(bal) / 1e8).toLocaleString(undefined, { maximumFractionDigits: 2 }) : "…"} <span style={{ fontSize: 12, color: "#5d6b80", fontWeight: 400 }}>CKB</span></div>
          <button onClick={disconnect} style={{ marginTop: 12, width: "100%", background: "transparent", color: C.mut, border: "1px solid #1f3a30", borderRadius: 9, padding: 9, font: "inherit", fontWeight: 500, cursor: "pointer" }}>Disconnect</button>
          <div>{faucetLink(CKB_FAUCET, "Pudge CKB faucet")}</div>
        </>
      ) : (
        <>
          <button onClick={open} style={{ width: "100%", background: C.green, color: "#06140d", border: 0, borderRadius: 9, padding: 11, font: "inherit", fontWeight: 600, cursor: "pointer" }}>Connect CKB wallet</button>
          <div style={{ fontSize: 11, color: "#5d6b80", marginTop: 8 }}>JoyID · MetaMask · UTXO Global · {faucetLink(CKB_FAUCET, "faucet")}</div>
        </>
      )}
    </div>
  );
}

function AdaCard({ cardano, onChange }) {
  const [picking, setPicking] = useState(false), [err, setErr] = useState(null), [busy, setBusy] = useState(false);
  const wallets = listCardanoWallets();
  const remembered = cardano ? null : rememberedWallet();   // offer a 1-click reconnect of the last wallet
  async function pick(key) { setPicking(false); setErr(null); setBusy(true); try { onChange(await connectCardano(key)); } catch (e) { setErr(String(e?.message || e)); } finally { setBusy(false); } }
  return (
    <div style={{ border: "1px solid #243049", borderTop: "2px solid " + C.blue, borderRadius: 14, background: "#0b101c", padding: "18px 20px", position: "relative" }}>
      <div style={{ fontFamily: mono, fontSize: 10.5, letterSpacing: ".1em", color: "#5a6f96", textTransform: "uppercase", marginBottom: 8 }}>Cardano · preview</div>
      <div style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 14, fontWeight: 600, marginBottom: 12 }}>
        <span style={{ width: 8, height: 8, borderRadius: "50%", background: cardano ? C.blue : C.off }} />
        {cardano ? cardano.name : "Wallet"}
      </div>
      {cardano ? (
        <>
          <CopyAddr value={cardano.addressHex} />
          <div style={{ fontSize: 13, color: cardano.networkId === 1 ? C.bad : C.dim }}>{cardano.networkId === 1 ? "MAINNET ⚠ switch to Preview" : "preview · connected"}</div>
          <button onClick={() => { forgetCardano(); onChange(null); }} style={{ marginTop: 12, width: "100%", background: "transparent", color: C.mut, border: "1px solid #243049", borderRadius: 9, padding: 9, font: "inherit", fontWeight: 500, cursor: "pointer" }}>Disconnect</button>
          <div>{faucetLink(ADA_FAUCET, "Preview ADA faucet")}</div>
        </>
      ) : remembered ? (
        <>
          <button onClick={() => pick(remembered.key)} disabled={busy} style={{ width: "100%", background: C.blue, color: "#06101f", border: 0, borderRadius: 9, padding: 11, font: "inherit", fontWeight: 600, cursor: busy ? "wait" : "pointer", display: "flex", alignItems: "center", justifyContent: "center", gap: 8 }}>
            {remembered.icon && <img src={remembered.icon} alt="" width="18" height="18" />} {busy ? "reconnecting…" : `Reconnect ${remembered.name}`}
          </button>
          <button onClick={() => { forgetCardano(); setPicking(true); }} style={{ width: "100%", marginTop: 8, background: "transparent", color: C.mut, border: "1px solid #243049", borderRadius: 9, padding: 8, font: "inherit", fontSize: 12, fontWeight: 500, cursor: "pointer" }}>Use another wallet</button>
        </>
      ) : (
        <>
          <button onClick={() => setPicking(true)} disabled={!wallets.length} style={{ width: "100%", background: C.blue, color: "#06101f", border: 0, borderRadius: 9, padding: 11, font: "inherit", fontWeight: 600, cursor: wallets.length ? "pointer" : "not-allowed", opacity: wallets.length ? 1 : .5 }}>Connect Cardano wallet</button>
          <div style={{ fontSize: 11, color: "#5d6b80", marginTop: 8 }}>{wallets.length ? "Lace · Eternl · Nami" : "no CIP-30 wallet found"} · {faucetLink(ADA_FAUCET, "faucet")}</div>
        </>
      )}
      {err && <div role="alert" style={{ color: C.bad, fontSize: 12, marginTop: 8 }}>{err}</div>}
      {picking && (
        <div onClick={() => setPicking(false)} style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,.6)", display: "flex", alignItems: "center", justifyContent: "center", zIndex: 100 }}>
          <div onClick={(e) => e.stopPropagation()} style={{ background: "#0e1422", border: "1px solid #243049", borderRadius: 12, padding: 18, minWidth: 280 }}>
            <h3 style={{ margin: "0 0 12px", fontSize: 14 }}>Choose a Cardano wallet</h3>
            {wallets.map((w) => (
              <button key={w.key} onClick={() => pick(w.key)} style={{ display: "flex", alignItems: "center", gap: 10, width: "100%", background: "#141b2a", color: C.fg, border: "1px solid #243049", borderRadius: 9, padding: 11, marginBottom: 8, font: "inherit", cursor: "pointer", justifyContent: "flex-start" }}>
                {w.icon && <img src={w.icon} alt="" width="20" height="20" />} {w.name}
              </button>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// ---------- stepper ----------
function Stepper({ labels, metas, phase, active }) {
  return (
    <div style={{ display: "flex", alignItems: "flex-start", marginBottom: 26 }}>
      {labels.map((label, i) => {
        const n = i + 1, done = phase > n, isActive = active === n || phase === n;
        const dotBg = done ? C.green : (isActive ? "rgba(107,155,255,.14)" : "#0c1018");
        const dotColor = done ? "#06101f" : (isActive ? C.blue : "#5d6b80");
        const dotBorder = done ? C.green : (isActive ? C.blue : "#28324a");
        return (
          <div key={i} style={{ flex: 1, display: "flex", flexDirection: "column", alignItems: "center", textAlign: "center", position: "relative" }}>
            {i > 0 && <div style={{ position: "absolute", top: 17, left: "-50%", width: "100%", height: 2, background: phase > i ? C.green : "#1c2740", zIndex: 0 }} />}
            <div style={{ position: "relative", zIndex: 1, width: 36, height: 36, borderRadius: "50%", display: "flex", alignItems: "center", justifyContent: "center", fontFamily: mono, fontWeight: 600, fontSize: 14, background: dotBg, color: dotColor, border: "1.5px solid " + dotBorder }}>{done ? "✓" : n}</div>
            <div style={{ fontSize: 12.5, fontWeight: 600, color: (done || isActive) ? C.fg : C.mut, marginTop: 10 }}>{label}</div>
            <div style={{ fontSize: 10.5, color: "#6f7d92", marginTop: 3, maxWidth: "16ch", lineHeight: 1.35 }}>{metas[i]}</div>
          </div>
        );
      })}
    </div>
  );
}

const flowCard = { border: "1px solid #1c2433", borderRadius: 18, background: "linear-gradient(180deg, #0d121d, #0a0e16)", padding: 30 };
const okRow = { display: "flex", justifyContent: "space-between", alignItems: "center", padding: "12px 15px", background: "#0a0f1a", fontSize: 13 };
const spinner = (color) => <div style={{ width: 44, height: 44, margin: "0 auto 16px", border: "3px solid #1c3a2e", borderTopColor: color, borderRadius: "50%", animation: "chiralSpin .9s linear infinite" }} />;
const primaryBtn = (bg, color, enabled) => ({ width: "100%", background: enabled ? bg : "#1a2233", color: enabled ? color : "#4a5b6b", border: 0, borderRadius: 11, padding: 15, font: "inherit", fontWeight: 600, fontSize: 15, cursor: enabled ? "pointer" : "not-allowed" });

// ---------- forward leap (CKB → Cardano) ----------
function Forward({ signer, cardano, cfg, onLock }) {
  const [amount, setAmount] = useState("");
  const [busy, setBusy] = useState(false), [status, setStatus] = useState(null), [err, setErr] = useState(null);
  const [lockTx, setLockTx] = useState(null), [mintParams, setMintParams] = useState(null), [mintTx, setMintTx] = useState(null);
  let recipient = null; try { recipient = cardano ? cardanoRecipientCred(cardano.addressHex) : null; } catch { /* bad */ }
  // live queue position for THIS prove (the client already knows lockTx) - only while the prove is in flight.
  const provePos = useJobPosition("prove", lockTx, busy && !!lockTx && !mintParams);
  const phase = mintTx ? 4 : mintParams ? 3 : lockTx ? 2 : 1;
  const ready = !!signer && !!cardano && !!cfg?.bridgeCodeHash && !!recipient && Number(amount) > 0;

  async function go() {
    setErr(null); setBusy(true);
    try {
      let tx = lockTx;
      if (!tx) { setStatus("locking CKB - approve in your CKB wallet…"); tx = await lockCkb({ signer, cfg, amountCKB: Number(amount), recipientCred28: recipient }); setLockTx(tx); onLock?.(tx); }
      let mp = mintParams;
      if (!mp) {
        setStatus("waiting for the lock to confirm on CKB…");
        await waitLockConfirmed(ckbClient, tx, { onTick: (s) => setStatus(`lock ${s}… then proving (~40–70s)`) });
        setStatus("proving CKB consensus in a Groth16 SNARK (~40–70s)…");
        mp = await requestProof(tx); setMintParams(mp);
      }
      if (!mintTx) { setStatus("minting χCKB - approve in your Cardano wallet…"); const t = await mintChiCKB({ cardanoApi: cardano.api, cardano, cfg, mintParams: mp }); setMintTx(t); }
      setStatus(null);
    } catch (e) { setErr(String(e?.message || e)); } finally { setBusy(false); }
  }
  function reset() { setLockTx(null); setMintParams(null); setMintTx(null); setStatus(null); setErr(null); setAmount(""); }

  return (
    <div style={flowCard}>
      <Stepper labels={["Lock CKB", "Relayer proves", "Mint χCKB"]} metas={["you sign · Nervos", "Groth16 of CKB consensus", "Plutus verifies · you sign"]} phase={phase} active={busy ? phase : 0} />
      <div style={{ height: 1, background: "#1a2233", margin: "0 0 24px" }} />
      {!signer || !cardano ? (
        <div style={{ textAlign: "center", padding: "30px 10px", color: C.mut }}><div style={{ fontSize: 28, marginBottom: 10, opacity: .5 }}>χ</div><div style={{ fontSize: 14.5 }}>Connect both wallets to begin a leap.</div></div>
      ) : phase >= 4 ? (
        <div style={{ textAlign: "center", padding: "6px 4px" }}>
          <div style={{ width: 52, height: 52, margin: "0 auto 16px", borderRadius: "50%", background: "linear-gradient(135deg, #6b9bff, #35d6a0)", display: "flex", alignItems: "center", justifyContent: "center", color: "#06101f", fontSize: 26, fontWeight: 700 }}>✓</div>
          <div style={{ fontSize: 18, fontWeight: 700, marginBottom: 6 }}>Leap complete</div>
          <div style={{ fontSize: 14, color: "#aeb9ca", marginBottom: 22 }}>{fmtCKB(mintParams.qty)} χCKB minted to your Cardano address.</div>
          <div style={{ display: "flex", flexDirection: "column", gap: 1, border: "1px solid #1c2740", borderRadius: 11, overflow: "hidden", textAlign: "left", marginBottom: 22 }}>
            <div style={okRow}><span style={{ color: "#8794a8" }}>CKB lock</span><a href={(cfg.ckbExplorer || "#") + lockTx} target="_blank" rel="noopener" style={{ fontFamily: mono, color: C.green }}>{shortHex(lockTx, 10, 8)}</a></div>
            <div style={okRow}><span style={{ color: "#8794a8" }}>χCKB mint</span><a href={(cfg.cardanoExplorer || "#") + mintTx} target="_blank" rel="noopener" style={{ fontFamily: mono, color: C.blue }}>{shortHex(mintTx, 10, 8)}</a></div>
          </div>
          <button onClick={reset} className="btn" style={{ background: "transparent", color: "#aab6c8", border: "1px solid #2b3445", borderRadius: 10, padding: "11px 22px", font: "inherit", fontWeight: 500, cursor: "pointer" }}>Run another leap</button>
        </div>
      ) : busy && status && status.includes("proving") ? (
        <div style={{ textAlign: "center", padding: "16px 10px" }}>
          {spinner(C.green)}
          <div style={{ fontSize: 15, fontWeight: 600, color: C.fg, marginBottom: 6 }}>
            {provePos && provePos.position > 0 ? `Waiting in line - ${provePos.position} ahead of you…` : "Relayer generating Groth16 proof…"}
          </div>
          <div style={{ fontSize: 13, color: C.dim, maxWidth: "44ch", margin: "0 auto" }}>Proving Eaglesong PoW + header-MMR membership + tx-inclusion of your lock against CKB consensus.</div>
        </div>
      ) : (
        <div>
          <label style={{ display: "block", fontSize: 12, color: "#8a96a8", marginBottom: 8 }}>Amount to lock on CKB</label>
          <div style={{ display: "flex", alignItems: "center", flex: 1, background: "#070b12", border: "1px solid #28324a", borderRadius: 10, padding: "0 14px", marginBottom: 18 }}>
            <input type="number" min={cfg?.minLockCKB || 300} step="1" value={amount} disabled={!!lockTx} onChange={(e) => setAmount(e.target.value)} placeholder={`min ${cfg?.minLockCKB || 300}`} aria-label="Amount to lock on CKB" aria-describedby="ckb-fund-hint" style={{ flex: 1, background: "transparent", border: 0, outline: "none", color: C.fg, font: "inherit", fontSize: 18, padding: "13px 0" }} />
            <span style={{ fontFamily: mono, fontSize: 13, color: "#5d6b80" }}>CKB</span>
          </div>
          <div id="ckb-fund-hint" style={{ fontSize: 11.5, color: "#6f7d92", marginTop: -10, marginBottom: 14, lineHeight: 1.5 }}>Fund from a single cell of ≥365 CKB (a fresh faucet cell qualifies) - a fragmented wallet shows a "consolidate" error.</div>
          <div style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 13, color: C.dim, marginBottom: 22 }}>→ χCKB to <span style={{ fontFamily: mono, color: C.blue }}>{recipient ? shortHex(recipient, 12, 8) : "-"}</span></div>
          {lockTx && <div style={{ fontSize: 12.5, color: C.green, marginBottom: 14 }}>✓ Locked <a href={(cfg.ckbExplorer || "#") + lockTx} target="_blank" rel="noopener" style={{ fontFamily: mono, color: C.green }}>{shortHex(lockTx, 12, 6)}</a></div>}
          <button onClick={go} disabled={!ready || busy} style={primaryBtn(C.green, "#06140d", ready && !busy)}>{busy ? "working…" : lockTx ? "Resume leap" : "Start leap"}</button>
        </div>
      )}
      {status && !status.includes("proving") && <div role="status" aria-live="polite" style={{ fontFamily: mono, fontSize: 12.5, color: C.blue, marginTop: 16 }}>⏳ {status}</div>}
      {err && <div role="alert" style={{ color: C.bad, fontSize: 12.5, marginTop: 12 }}>{err}</div>}
    </div>
  );
}

// ---------- native ADA → CKB leap (lock ADA → mint χADA xUDT on CKB) ----------
// The mirror of Forward: the user locks real preview ADA at the escrow (signs on Cardano), and the relayer mints
// χADA to their CKB wallet once Mithril certifies the lock. Because Mithril certification is unbounded (like the
// release leg), the mint step polls - it auto-retries, then offers Resume if the aggregator is slow.
function ForwardAda({ signer, cardano, cfg, xcfg }) {
  const [amount, setAmount] = useState("");
  const [busy, setBusy] = useState(false), [status, setStatus] = useState(null), [err, setErr] = useState(null);
  const [pending, setPending] = useState(null);   // { escrowTxid, amountLovelace, recipientLock } after the lock
  const [mint, setMint] = useState(null);
  const lo = xcfg?.minAda || 2, hi = xcfg?.demoMaxAda || 5;
  const phase = mint?.minted ? 4 : pending ? 2 : 1;
  const ready = !!signer && !!cardano && !!xcfg?.ready && Number(amount) >= lo && Number(amount) <= hi;

  async function pollMint(p) {
    for (let i = 0; i < 30; i++) {
      const res = await requestXadaMint(p);
      if (res.minted) { setMint(res); return true; }
      setStatus(`Mithril certifying your ADA lock - minting as soon as it lands (check ${i + 1})…`);
      await new Promise((r) => setTimeout(r, 20000));
    }
    return false;
  }

  async function go() {
    setErr(null); setBusy(true);
    try {
      let p = pending;
      if (!p) {
        if (cardano.networkId === 1) throw new Error("switch your Cardano wallet to Preview testnet");
        setStatus("preparing your CKB recipient…");
        const lockObj = (await signer.getRecommendedAddressObj()).script;
        const recipientLock = { codeHash: lockObj.codeHash, hashType: lockObj.hashType, args: lockObj.args };
        const ckbRecipientHash = lockObj.hash();
        setStatus("locking ADA - approve in your Cardano wallet…");
        const escrowTxid = await lockAda({ cardanoApi: cardano.api, bridgeCfg: cfg, xcfg, amountAda: Number(amount), ckbRecipientHash, nonce: Date.now() });
        p = { escrowTxid, amountLovelace: Math.round(Number(amount) * 1e6), recipientLock };
        setPending(p);
      }
      setStatus("Mithril certifying your lock, then minting χADA (a few minutes)…");
      if (!(await pollMint(p))) setStatus("Mithril hasn't certified yet - hit Resume in a moment.");
      else setStatus(null);
    } catch (e) { setErr(String(e?.message || e)); } finally { setBusy(false); }
  }
  function reset() { setPending(null); setMint(null); setStatus(null); setErr(null); setAmount(""); }

  return (
    <div style={flowCard}>
      <Stepper labels={["Lock ADA", "Certify", "Mint χADA"]} metas={["you sign · Cardano", "Mithril certifies the lock", "relayer mints to you · CKB"]} phase={phase} active={busy ? phase : 0} />
      <div style={{ height: 1, background: "#1a2233", margin: "0 0 24px" }} />
      {!signer || !cardano ? (
        <div style={{ textAlign: "center", padding: "30px 10px", color: C.mut }}><div style={{ fontSize: 28, marginBottom: 10, opacity: .5 }}>χ</div><div style={{ fontSize: 14.5 }}>Connect both wallets to leap ADA → CKB.</div></div>
      ) : phase >= 4 ? (
        <div style={{ textAlign: "center", padding: "6px 4px" }}>
          <div style={{ width: 52, height: 52, margin: "0 auto 16px", borderRadius: "50%", background: "linear-gradient(135deg, #6b9bff, #35d6a0)", display: "flex", alignItems: "center", justifyContent: "center", color: "#06101f", fontSize: 26, fontWeight: 700 }}>✓</div>
          <div style={{ fontSize: 18, fontWeight: 700, marginBottom: 6 }}>χADA minted</div>
          <div style={{ fontSize: 14, color: "#aeb9ca", marginBottom: 22 }}>{(Number(mint.amount) / 1e6).toLocaleString()} χADA xUDT minted to your CKB wallet - 1:1 with the ADA you locked.</div>
          <div style={{ display: "flex", flexDirection: "column", gap: 1, border: "1px solid #1c2740", borderRadius: 11, overflow: "hidden", textAlign: "left", marginBottom: 16 }}>
            <div style={okRow}><span style={{ color: "#8794a8" }}>ADA lock</span><a href={(xcfg.cardanoExplorer || "#") + pending.escrowTxid} target="_blank" rel="noopener" style={{ fontFamily: mono, color: C.blue }}>{shortHex(pending.escrowTxid, 10, 8)}</a></div>
            <div style={okRow}><span style={{ color: "#8794a8" }}>χADA mint</span><a href={(xcfg.ckbExplorer || "#") + mint.mintTxid} target="_blank" rel="noopener" style={{ fontFamily: mono, color: C.green }}>{shortHex(mint.mintTxid, 10, 8)}</a></div>
          </div>
          <div style={{ fontSize: 11.5, color: "#7c8ba1", marginBottom: 20, lineHeight: 1.5 }}>The χADA → ADA return (burn → release) is <strong style={{ color: "#9aa6ba" }}>P5</strong> - not yet live, so this leg is one-way for now.</div>
          <button onClick={reset} className="btn" style={{ background: "transparent", color: "#aab6c8", border: "1px solid #2b3445", borderRadius: 10, padding: "11px 22px", font: "inherit", fontWeight: 500, cursor: "pointer" }}>Leap more ADA</button>
        </div>
      ) : busy && status && (status.includes("certif") || status.includes("minting")) ? (
        <div style={{ textAlign: "center", padding: "16px 10px" }}>
          {spinner(C.blue)}
          <div style={{ fontSize: 15, fontWeight: 600, color: C.fg, marginBottom: 6 }}>Certifying your lock + minting χADA…</div>
          <div style={{ fontSize: 13, color: C.dim, maxWidth: "46ch", margin: "0 auto" }}>Mithril certifies your Cardano lock, then the relayer verifies that certificate in CKB-VM and mints χADA to you - keyless. This can take a few minutes.</div>
          {pending && <div style={{ fontSize: 12, color: C.mut, marginTop: 12 }}>ADA locked: <a href={(xcfg.cardanoExplorer || "#") + pending.escrowTxid} target="_blank" rel="noopener" style={{ fontFamily: mono, color: C.blue }}>{shortHex(pending.escrowTxid, 10, 6)}</a></div>}
        </div>
      ) : (
        <div>
          <label style={{ display: "block", fontSize: 12, color: "#8a96a8", marginBottom: 8 }}>Amount of ADA to lock</label>
          <div style={{ display: "flex", alignItems: "center", background: "#070b12", border: "1px solid #28324a", borderRadius: 10, padding: "0 14px", marginBottom: 16 }}>
            <input type="number" min={lo} max={hi} step="0.5" value={amount} disabled={!!pending} onChange={(e) => setAmount(e.target.value)} placeholder={`${lo}–${hi} ADA`} aria-label="Amount of ADA to lock" style={{ flex: 1, background: "transparent", border: 0, outline: "none", color: C.fg, font: "inherit", fontSize: 18, padding: "13px 0" }} />
            <span style={{ fontFamily: mono, fontSize: 13, color: "#5d6b80" }}>ADA</span>
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 13, color: C.dim, marginBottom: 18 }}>→ χADA xUDT to your <span style={{ color: C.green, fontWeight: 600 }}>CKB</span> wallet</div>
          <div style={{ fontSize: 11.5, color: C.warn, background: "rgba(210,153,34,.07)", border: "1px solid rgba(210,153,34,.2)", borderRadius: 8, padding: "9px 11px", marginBottom: 16, lineHeight: 1.45 }}>Experiment cap: ≤{hi} ADA. The escrow's return path is a placeholder vk (P5), so locks are kept small and one-way for now.</div>
          {pending && <div style={{ fontSize: 12.5, color: C.blue, marginBottom: 14 }}>✓ Locked <a href={(xcfg.cardanoExplorer || "#") + pending.escrowTxid} target="_blank" rel="noopener" style={{ fontFamily: mono, color: C.blue }}>{shortHex(pending.escrowTxid, 12, 6)}</a></div>}
          <button onClick={go} disabled={!ready || busy} style={primaryBtn(C.blue, "#06101f", ready && !busy)}>{busy ? "working…" : pending ? "Resume mint" : "Start leap"}</button>
        </div>
      )}
      {status && busy && !(status.includes("certif") || status.includes("minting")) && <div role="status" aria-live="polite" style={{ fontFamily: mono, fontSize: 12.5, color: C.blue, marginTop: 16 }}>⏳ {status}</div>}
      {err && <div role="alert" style={{ color: C.bad, fontSize: 12.5, marginTop: 12 }}>{err}</div>}
    </div>
  );
}

// ---------- reverse leap (Cardano → CKB) ----------
function Reverse({ signer, cardano, cfg, receiptTx }) {
  const [amount, setAmount] = useState(""), [receipt, setReceipt] = useState("");
  const [busy, setBusy] = useState(false), [status, setStatus] = useState(null), [err, setErr] = useState(null);
  const [burnTx, setBurnTx] = useState(null), [release, setRelease] = useState(null);
  const receiptId = receiptTx || receipt;
  const phase = release?.released ? 4 : burnTx ? 2 : 1;
  const ready = !!signer && !!cardano && !!cfg?.cardano?.mintScriptHex && Number(amount) > 0 && !!receiptId;

  async function go() {
    setErr(null); setBusy(true);
    try {
      if (!receiptId) throw new Error("enter your original lock tx (the receipt to release)");
      let bt = burnTx;
      if (!bt) { setStatus("burning χCKB - approve in your Cardano wallet…"); const qty = BigInt(Math.round(Number(amount) * 1e8)); bt = await burnChiCKB({ cardanoApi: cardano.api, cfg, qty }); setBurnTx(bt); }
      if (!release?.released) { setStatus("certifying the burn + advancing the light-client, then releasing (a few minutes)…"); const ckbAddr = await signer.getRecommendedAddress(); setRelease(await requestRelease(bt, receiptId, ckbAddr)); }
      setStatus(null);
    } catch (e) { setErr(String(e?.message || e)); } finally { setBusy(false); }
  }
  function reset() { setBurnTx(null); setRelease(null); setStatus(null); setErr(null); setAmount(""); setReceipt(""); }

  return (
    <div style={flowCard}>
      <Stepper labels={["Burn χCKB", "Certify + advance", "Release CKB"]} metas={["you sign · Cardano", "Mithril cert in CKB-VM", "keyless · no key signs"]} phase={phase} active={busy ? phase : 0} />
      <div style={{ height: 1, background: "#1a2233", margin: "0 0 24px" }} />
      {!signer || !cardano ? (
        <div style={{ textAlign: "center", padding: "30px 10px", color: C.mut }}><div style={{ fontSize: 28, marginBottom: 10, opacity: .5 }}>χ</div><div style={{ fontSize: 14.5 }}>Connect both wallets to release CKB.</div></div>
      ) : phase >= 4 ? (
        <div style={{ textAlign: "center", padding: "6px 4px" }}>
          <div style={{ width: 52, height: 52, margin: "0 auto 16px", borderRadius: "50%", background: "linear-gradient(135deg, #35d6a0, #6b9bff)", display: "flex", alignItems: "center", justifyContent: "center", color: "#06101f", fontSize: 26, fontWeight: 700 }}>✓</div>
          <div style={{ fontSize: 18, fontWeight: 700, marginBottom: 6 }}>Round trip closed</div>
          <div style={{ fontSize: 14, color: "#aeb9ca", marginBottom: 22 }}>{release.releasedCKB} CKB released to your address - keyless, gated by the certified burn.</div>
          <div style={{ display: "flex", flexDirection: "column", gap: 1, border: "1px solid #1c2740", borderRadius: 11, overflow: "hidden", textAlign: "left", marginBottom: 22 }}>
            <div style={okRow}><span style={{ color: "#8794a8" }}>χCKB burn</span><a href={(cfg.cardanoExplorer || "#") + burnTx} target="_blank" rel="noopener" style={{ fontFamily: mono, color: C.blue }}>{shortHex(burnTx, 10, 8)}</a></div>
            <div style={okRow}><span style={{ color: "#8794a8" }}>CKB release</span><a href={(cfg.ckbExplorer || "#") + release.releaseTxid} target="_blank" rel="noopener" style={{ fontFamily: mono, color: C.green }}>{shortHex(release.releaseTxid, 10, 8)}</a></div>
          </div>
          <button onClick={reset} className="btn" style={{ background: "transparent", color: "#aab6c8", border: "1px solid #2b3445", borderRadius: 10, padding: "11px 22px", font: "inherit", fontWeight: 500, cursor: "pointer" }}>Reverse again</button>
        </div>
      ) : busy && status && status.includes("light-client") ? (
        <div style={{ textAlign: "center", padding: "16px 10px" }}>
          {spinner(C.blue)}
          <div style={{ fontSize: 15, fontWeight: 600, color: C.fg, marginBottom: 6 }}>Releasing your CKB…</div>
          <div style={{ fontSize: 13, color: C.dim, maxWidth: "46ch", margin: "0 auto" }}>Verifying the Mithril cert in CKB-VM, advancing the light-client, and spending the receipt - keyless. This can take a few minutes.</div>
        </div>
      ) : (
        <div>
          <label style={{ display: "block", fontSize: 12, color: "#8a96a8", marginBottom: 8 }}>Amount of χCKB to burn</label>
          <div style={{ display: "flex", alignItems: "center", background: "#070b12", border: "1px solid #28324a", borderRadius: 10, padding: "0 14px", marginBottom: 16 }}>
            <input type="number" min="1" step="1" value={amount} disabled={!!burnTx} onChange={(e) => setAmount(e.target.value)} placeholder="χCKB" aria-label="Amount of χCKB to burn" style={{ flex: 1, background: "transparent", border: 0, outline: "none", color: C.fg, font: "inherit", fontSize: 18, padding: "13px 0" }} />
            <span style={{ fontFamily: mono, fontSize: 13, color: "#5d6b80" }}>χCKB</span>
          </div>
          {!receiptTx && (
            <>
              <label style={{ display: "block", fontSize: 12, color: "#8a96a8", marginBottom: 8 }}>Your original lock tx (the receipt to release)</label>
              <div style={{ display: "flex", alignItems: "center", background: "#070b12", border: "1px solid #28324a", borderRadius: 10, padding: "0 14px", marginBottom: 18 }}>
                <input value={receipt} disabled={!!burnTx} onChange={(e) => setReceipt(e.target.value)} placeholder="0x…" aria-label="Your original lock tx - the receipt to release" style={{ flex: 1, background: "transparent", border: 0, outline: "none", color: C.fg, font: "inherit", fontFamily: mono, fontSize: 13, padding: "13px 0" }} />
              </div>
            </>
          )}
          {burnTx && <div style={{ fontSize: 12.5, color: C.blue, marginBottom: 14 }}>✓ Burned <a href={(cfg.cardanoExplorer || "#") + burnTx} target="_blank" rel="noopener" style={{ fontFamily: mono, color: C.blue }}>{shortHex(burnTx, 12, 6)}</a></div>}
          {release && release.certified === false && <div style={{ fontSize: 12.5, color: C.warn, marginBottom: 14 }}>Burn not yet Mithril-certified - the aggregator certifies on a schedule. Hit Resume shortly.</div>}
          <button onClick={go} disabled={!ready || busy} style={primaryBtn(C.blue, "#06101f", ready && !busy)}>{busy ? "working…" : burnTx ? "Resume release" : "Start reverse"}</button>
        </div>
      )}
      {status && !status.includes("light-client") && <div role="status" aria-live="polite" style={{ fontFamily: mono, fontSize: 12.5, color: C.blue, marginTop: 16 }}>⏳ {status}</div>}
      {err && <div role="alert" style={{ color: C.bad, fontSize: 12.5, marginTop: 12 }}>{err}</div>}
    </div>
  );
}

// ---------- χADA → ADA return (burn χADA on CKB → on-chain Groth16 verify → release ADA) ----------
// The relayer-driven half of the return: given a confirmed CKB χADA-burn tx, the backend captures it, re-anchors
// the CKB-header checkpoint, proves the burn (reusing the burn key), and spends ada_escrow.Release (the Cardano
// node verifies the Groth16 proof on-chain) to pay the ADA to the burn's bound recipient. (Burning χADA itself
// is owner-mode/relayer-assisted - for now paste the burn tx here; a one-click burn is the next increment.)
function ReturnAda({ signer, cardano, xcfg }) {
  const [amount, setAmount] = useState("");
  const [busy, setBusy] = useState(false), [status, setStatus] = useState(null), [err, setErr] = useState(null);
  const [burnTx, setBurnTx] = useState(null), [result, setResult] = useState(null);
  let recipient = null; try { recipient = cardano ? cardanoRecipientCred(cardano.addressHex) : null; } catch { /* */ }
  const phase = result?.released ? 4 : burnTx ? 3 : busy ? 2 : 1;
  const ready = !!signer && !!cardano && !!recipient && Number(amount) > 0;

  async function go() {
    setErr(null); setBusy(true);
    try {
      let bt = burnTx;
      if (!bt) {
        if (cardano.networkId === 1) throw new Error("switch your Cardano wallet to Preview testnet");
        const lockObj = (await signer.getRecommendedAddressObj()).script;
        const recipientLock = { codeHash: lockObj.codeHash, hashType: lockObj.hashType, args: lockObj.args };
        setStatus("building your burn… approve the χADA burn in your CKB wallet");
        const built = await buildXadaBurn({ recipientLock, amount: Math.round(Number(amount) * 1e6), cardanoRecipient: recipient });
        const tx = ccc.Transaction.fromBytes(ccc.bytesFrom(built.txHex));
        const signed = await signer.signTransaction(tx);     // user signs ONLY their χADA input
        setStatus("submitting the burn…");
        const sub = await submitXadaBurn({ signedTxHex: ccc.hexFrom(signed.toBytes()) });
        bt = sub.burnTxid; setBurnTx(bt);
      }
      setStatus("burn confirmed - re-anchoring the checkpoint, proving, releasing your ADA (a few minutes)…");
      setResult(await requestXadaReturn({ burnTxid: bt }));
      setStatus(null);
    } catch (e) { setErr(String(e?.message || e)); } finally { setBusy(false); }
  }
  function reset() { setAmount(""); setBurnTx(null); setResult(null); setStatus(null); setErr(null); }

  return (
    <div style={flowCard}>
      <Stepper labels={["Burn χADA", "Prove burn", "Release ADA"]} metas={["you sign · CKB", "Groth16 of the CKB burn", "Plutus verifies · keyless"]} phase={phase} active={busy ? phase : 0} />
      <div style={{ height: 1, background: "#1a2233", margin: "0 0 24px" }} />
      {!signer || !cardano ? (
        <div style={{ textAlign: "center", padding: "30px 10px", color: C.mut }}><div style={{ fontSize: 28, marginBottom: 10, opacity: .5 }}>χ</div><div style={{ fontSize: 14.5 }}>Connect both wallets to return χADA → ADA.</div></div>
      ) : phase >= 4 ? (
        <div style={{ textAlign: "center", padding: "6px 4px" }}>
          <div style={{ width: 52, height: 52, margin: "0 auto 16px", borderRadius: "50%", background: "linear-gradient(135deg, #35d6a0, #6b9bff)", display: "flex", alignItems: "center", justifyContent: "center", color: "#06101f", fontSize: 26, fontWeight: 700 }}>✓</div>
          <div style={{ fontSize: 18, fontWeight: 700, marginBottom: 6 }}>ADA released</div>
          <div style={{ fontSize: 14, color: "#aeb9ca", marginBottom: 22 }}>{result.releasedAda} ADA back to your Cardano wallet - the node verified the Groth16 proof of your CKB burn, keyless.</div>
          <div style={{ display: "flex", flexDirection: "column", gap: 1, border: "1px solid #1c2740", borderRadius: 11, overflow: "hidden", textAlign: "left", marginBottom: 22 }}>
            <div style={okRow}><span style={{ color: "#8794a8" }}>χADA burn</span><a href={(xcfg.ckbExplorer || "#") + burnTx} target="_blank" rel="noopener" style={{ fontFamily: mono, color: C.green }}>{shortHex(burnTx, 10, 8)}</a></div>
            <div style={okRow}><span style={{ color: "#8794a8" }}>ADA release</span><a href={(xcfg.cardanoExplorer || "#") + result.releaseTxid} target="_blank" rel="noopener" style={{ fontFamily: mono, color: C.blue }}>{shortHex(result.releaseTxid, 10, 8)}</a></div>
          </div>
          <button onClick={reset} className="btn" style={{ background: "transparent", color: "#aab6c8", border: "1px solid #2b3445", borderRadius: 10, padding: "11px 22px", font: "inherit", fontWeight: 500, cursor: "pointer" }}>Return more</button>
        </div>
      ) : busy && phase === 3 ? (
        <div style={{ textAlign: "center", padding: "16px 10px" }}>
          {spinner(C.blue)}
          <div style={{ fontSize: 15, fontWeight: 600, color: C.fg, marginBottom: 6 }}>Proving your burn + releasing ADA…</div>
          <div style={{ fontSize: 13, color: C.dim, maxWidth: "46ch", margin: "0 auto" }}>Re-anchoring the CKB-header checkpoint, generating a Groth16 proof of your burn, and spending the escrow - the Cardano node verifies the proof on-chain. A few minutes.</div>
          {burnTx && <div style={{ fontSize: 12, color: C.mut, marginTop: 12 }}>burned: <a href={(xcfg.ckbExplorer || "#") + burnTx} target="_blank" rel="noopener" style={{ fontFamily: mono, color: C.green }}>{shortHex(burnTx, 10, 6)}</a></div>}
        </div>
      ) : (
        <div>
          <label style={{ display: "block", fontSize: 12, color: "#8a96a8", marginBottom: 8 }}>Amount of χADA to return</label>
          <div style={{ display: "flex", alignItems: "center", background: "#070b12", border: "1px solid #28324a", borderRadius: 10, padding: "0 14px", marginBottom: 16 }}>
            <input type="number" min="0.5" step="0.5" value={amount} disabled={!!burnTx} onChange={(e) => setAmount(e.target.value)} placeholder="χADA" aria-label="Amount of χADA to return" style={{ flex: 1, background: "transparent", border: 0, outline: "none", color: C.fg, font: "inherit", fontSize: 18, padding: "13px 0" }} />
            <span style={{ fontFamily: mono, fontSize: 13, color: "#5d6b80" }}>χADA</span>
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 13, color: C.dim, marginBottom: 18 }}>→ {amount || "-"} ADA back to your <span style={{ color: C.blue, fontWeight: 600 }}>Cardano</span> wallet</div>
          {burnTx && <div style={{ fontSize: 12.5, color: C.green, marginBottom: 14 }}>✓ Burned <a href={(xcfg.ckbExplorer || "#") + burnTx} target="_blank" rel="noopener" style={{ fontFamily: mono, color: C.green }}>{shortHex(burnTx, 12, 6)}</a></div>}
          <button onClick={go} disabled={!ready || busy} style={primaryBtn(C.blue, "#06101f", ready && !busy)}>{busy ? "working…" : burnTx ? "Resume return" : "Burn & return"}</button>
        </div>
      )}
      {status && busy && phase !== 3 && <div role="status" aria-live="polite" style={{ fontFamily: mono, fontSize: 12.5, color: C.blue, marginTop: 16 }}>⏳ {status}</div>}
      {err && <div role="alert" style={{ color: C.bad, fontSize: 12.5, marginTop: 12 }}>{err}</div>}
    </div>
  );
}

// ---------- guided tour (for non-technical first-timers) ----------
const wlink = (w) => <a key={w.name} href={w.url} target="_blank" rel="noopener" className="lk" style={{ color: C.blue, textDecoration: "none", fontWeight: 600 }}>{w.name}</a>;
const TOUR_STEPS = [
  { title: "Welcome - this is an experiment", body: (
    <>You're about to move test tokens between two blockchains - <b style={{ color: C.green }}>Nervos CKB</b> and <b style={{ color: C.blue }}>Cardano</b> - with a cryptographic proof, no trusted middleman. It runs on <b>testnet</b>: the coins are free and have <b>no real value</b>. Nothing here can touch real money. Takes ~5 minutes. Want the quick tour?</> ) },
  { title: "1 · Get two free wallets", body: (
    <>You need one browser wallet per chain (free, ~2 min each):<div style={{ marginTop: 10, lineHeight: 2 }}>
      <div><span style={{ color: C.green, fontFamily: mono, fontSize: 12 }}>CKB</span> &nbsp;{WALLETS.ckb.map((w, i) => <span key={w.name}>{i > 0 && " · "}{wlink(w)} <span style={{ color: C.mut, fontSize: 12 }}>({w.note})</span></span>)}</div>
      <div><span style={{ color: C.blue, fontFamily: mono, fontSize: 12 }}>ADA</span> &nbsp;{WALLETS.ada.map((w, i) => <span key={w.name}>{i > 0 && " · "}{wlink(w)} <span style={{ color: C.mut, fontSize: 12 }}>({w.note})</span></span>)}</div>
    </div><div style={{ marginTop: 10, color: C.mut, fontSize: 12.5 }}>Install, then come back to this page.</div></> ) },
  { title: "2 · Grab free test coins", body: (
    <>Testnet coins come from “faucets” (free dispensers). You'll want a little on each side:<div style={{ marginTop: 10, lineHeight: 1.9 }}>
      <div>{faucetLink(CKB_FAUCET, "Pudge CKB faucet")} <span style={{ color: C.mut, fontSize: 12 }}>- paste your CKB address</span></div>
      <div>{faucetLink(ADA_FAUCET, "Preview ADA faucet")} <span style={{ color: C.mut, fontSize: 12 }}>- paste your Cardano address</span></div>
    </div><div style={{ marginTop: 10, color: C.mut, fontSize: 12.5 }}>Tip: each wallet card below has a copy button + its faucet link once connected.</div></> ) },
  { title: "3 · Connect both wallets", body: (
    <>On the left you'll see two cards - <b style={{ color: C.green }}>Nervos CKB</b> and <b style={{ color: C.blue }}>Cardano</b>. Click <b>Connect</b> on each and approve in the wallet popup. Make sure Cardano is on <b>Preview</b> testnet. When both show a colored dot, you're ready.</> ) },
  { title: "4 · Pick a direction & leap", body: (
    <>Choose a direction at the top of the panel:<div style={{ marginTop: 10, lineHeight: 1.7, fontSize: 13 }}>
      <div><b style={{ color: C.green }}>CKB → Cardano</b> - lock CKB, get wrapped <b>χCKB</b> on Cardano.</div>
      <div><b style={{ color: C.blue }}>Cardano → CKB</b> - lock ADA, get wrapped <b>χADA</b> on CKB.</div>
      <div><b>Unwind χCKB</b> - burn χCKB to reclaim your original CKB.</div>
    </div><div style={{ marginTop: 12 }}>Start with a <b>small</b> amount. Click <b>Start</b> - your wallet will ask you to approve each step. The relayer only supplies the proof; it can never move your funds.</div></> ) },
];
function GuidedTour({ onClose }) {
  const [i, setI] = useState(0);
  const last = i === TOUR_STEPS.length - 1;
  const close = (dont) => { if (dont) { try { localStorage.setItem("chiral.tour.seen", "1"); } catch { /* */ } } onClose(); };
  const s = TOUR_STEPS[i];
  return (
    <div onClick={() => close(false)} style={{ position: "fixed", inset: 0, background: "rgba(4,7,12,.74)", display: "flex", alignItems: "center", justifyContent: "center", zIndex: 200, padding: 20 }}>
      <div onClick={(e) => e.stopPropagation()} style={{ background: "#0d1320", border: "1px solid #243049", borderTop: "3px solid " + C.blue, borderRadius: 16, padding: "26px 28px", maxWidth: 480, width: "100%", boxShadow: "0 20px 60px rgba(0,0,0,.5)" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 14 }}>
          <span style={{ fontFamily: mono, fontSize: 10.5, letterSpacing: ".12em", color: C.mut, textTransform: "uppercase" }}>Guided tour</span>
          <span onClick={() => close(false)} style={{ cursor: "pointer", color: C.mut, fontSize: 18, lineHeight: 1 }}>✕</span>
        </div>
        <h3 style={{ margin: "0 0 12px", fontSize: 19, color: C.fg }}>{s.title}</h3>
        <div style={{ fontSize: 14, color: "#c4cedd", lineHeight: 1.6, minHeight: 96 }}>{s.body}</div>
        <div style={{ display: "flex", gap: 6, margin: "20px 0 18px" }}>
          {TOUR_STEPS.map((_, k) => <span key={k} style={{ flex: 1, height: 3, borderRadius: 2, background: k <= i ? C.blue : "#1c2740" }} />)}
        </div>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <button onClick={() => close(true)} style={{ background: "transparent", color: C.mut, border: 0, font: "inherit", fontSize: 12.5, cursor: "pointer" }}>Skip · don't show again</button>
          <div style={{ display: "flex", gap: 8 }}>
            {i > 0 && <button onClick={() => setI(i - 1)} style={{ background: "transparent", color: "#aab6c8", border: "1px solid #2b3445", borderRadius: 9, padding: "9px 16px", font: "inherit", fontWeight: 500, cursor: "pointer" }}>Back</button>}
            <button onClick={() => (last ? close(true) : setI(i + 1))} style={{ background: C.blue, color: "#06101f", border: 0, borderRadius: 9, padding: "9px 20px", font: "inherit", fontWeight: 600, cursor: "pointer" }}>{last ? "Let's go" : (i === 0 ? "Show me" : "Next")}</button>
          </div>
        </div>
      </div>
    </div>
  );
}

// ---------- support / donations (a donation, NOT an investment - testnet tokens have no value) ----------
function Support() {
  const tips = [["ADA", DONATE.ada], ["BTC", DONATE.btc]].filter(([, v]) => v);
  return (
    <div style={{ fontSize: 11.5, color: "#6f7d92", lineHeight: 1.55, borderTop: "1px solid #1a2233", paddingTop: 14 }}>
      <div style={{ color: "#8794a8", fontWeight: 600, marginBottom: 4 }}>Support this experiment</div>
      Chiral is independent R&D by <a href={DONATE.github} target="_blank" rel="noopener" className="lk" style={{ color: "#8da0c4", textDecoration: "none" }}>LusoCryptoLabs</a>. If it's useful, you can help fund continued work - a donation, not an investment.
      {tips.map(([sym, addr]) => (
        <div key={sym} style={{ marginTop: 8 }}>
          <span style={{ fontFamily: mono, fontSize: 11, color: sym === "ADA" ? C.blue : C.warn }}>{sym}</span>{" "}
          <span onClick={() => { try { navigator.clipboard.writeText(addr); } catch { /* */ } }} title="click to copy" style={{ fontFamily: mono, fontSize: 11, color: "#c4cedd", cursor: "pointer", wordBreak: "break-all" }}>{shortHex(addr, 12, 8)} ⧉</span>
        </div>
      ))}
    </div>
  );
}

// ---------- shared relayer load banner (honest backpressure) ----------
// The relayer serializes heavy ops; this turns the wait into visible status for ALL legs. Shows the warm
// state (cold first proof = minutes; warm = ~10s) and, when busy, what's running so a queued user sees the
// line is real, not hung. Hidden when the relayer is idle.
function RelayBanner() {
  const health = useRelayLoad();
  if (!health) return null;
  const summary = loadSummary(health);
  const warm = health.warm;
  const tone = summary ? C.warn : C.green;
  return (
    <div role="status" aria-live="polite" style={{ display: "flex", alignItems: "center", gap: 10, padding: "9px 13px", border: "1px solid " + (summary ? "#3a3320" : "#1c2433"), background: summary ? "#16130a" : "#0a0e16", borderRadius: 10, fontSize: 12.5 }}>
      <span aria-hidden="true" style={{ width: 7, height: 7, borderRadius: "50%", background: tone, boxShadow: `0 0 7px ${tone}`, flex: "0 0 auto" }} />
      <span style={{ color: summary ? "#e3b341" : C.mut, fontWeight: 600 }}>
        {summary ? `Relayer busy - ${summary}` : "Relayer idle"}
      </span>
      <span style={{ marginLeft: "auto", fontFamily: mono, fontSize: 11, color: warm ? C.green : C.warn }}>
        {warm ? "warm ✓ ~10s proofs" : "cold · first proof ~min"}
      </span>
    </div>
  );
}

// ---------- app ----------
function LeapApp() {
  const signer = ccc.useSigner();
  const [cardano, setCardano] = useState(null);
  const [cfg, setCfg] = useState(null);
  const [xcfg, setXcfg] = useState(null);
  const [dir, setDir] = useState("forward");
  const [receiptTx, setReceiptTx] = useState(null);
  const [tour, setTour] = useState(false);
  useEffect(() => { fetch("/api/bridge/config").then((r) => r.json()).then(setCfg).catch(() => setCfg({})); }, []);
  useEffect(() => { fetchXadaConfig().then(setXcfg).catch(() => setXcfg({})); }, []);
  useEffect(() => { reconnectCardano().then((c) => { if (c) setCardano(c); }).catch(() => {}); }, []);   // restore Cardano wallet on reload
  useEffect(() => { try { if (!localStorage.getItem("chiral.tour.seen")) setTour(true); } catch { /* */ } }, []);   // first-visit tour

  const pill = (active) => ({ flex: 1, padding: "9px 10px", borderRadius: 9, border: "1px solid " + (active ? "#2e3c5a" : "transparent"), background: active ? "#121a2b" : "transparent", color: active ? C.fg : C.mut, fontWeight: 600, fontSize: 12.5, cursor: "pointer", textAlign: "center", lineHeight: 1.25 });
  const sub = (active) => ({ display: "block", fontSize: 10, fontWeight: 500, color: active ? "#8da0c4" : "#5d6b80", marginTop: 2 });

  return (
    <div style={{ display: "grid", gridTemplateColumns: "340px 1fr", gap: 22, alignItems: "start" }}>
      <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
        <CkbCard />
        <AdaCard cardano={cardano} onChange={setCardano} />
        <div style={{ fontSize: 11.5, color: "#6f7d92", lineHeight: 1.55, borderTop: "1px solid #1a2233", paddingTop: 14 }}>Self-custody: the relayer only supplies the cross-chain proof. It can never move your funds. Testnet, no real value.</div>
        <Support />
      </div>
      <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: -2 }}>
          <span style={{ fontSize: 12, color: C.mut }}>New here? Take the {""}<a onClick={() => setTour(true)} style={{ color: C.blue, cursor: "pointer", textDecoration: "none", fontWeight: 600 }} className="lk">guided tour</a>.</span>
          <button onClick={() => setTour(true)} title="Guided tour" style={{ background: "transparent", color: C.mut, border: "1px solid #243049", borderRadius: 8, padding: "5px 11px", font: "inherit", fontSize: 12, fontWeight: 600, cursor: "pointer" }}>? Guide me</button>
        </div>
        {typeof window !== "undefined" && !window.isSecureContext && (
          <div role="alert" style={{ display: "flex", gap: 9, padding: "9px 13px", border: "1px solid #3a3320", background: "#16130a", borderRadius: 10, fontSize: 12.5, color: "#e3b341", lineHeight: 1.5 }}>
            <span aria-hidden="true">⚠</span>
            <span>Insecure connection (HTTP). Some wallets require HTTPS and may fail to connect - open the operator-provided link, and tell the operator if a wallet won't connect.</span>
          </div>
        )}
        <RelayBanner />
        <div role="group" aria-label="Leap direction" style={{ display: "flex", gap: 5, padding: 5, border: "1px solid #1c2433", borderRadius: 12, background: "#0a0e16" }}>
          {[
            ["forward", "CKB → Cardano", "mint χCKB"],
            ["ada2ckb", "Cardano → CKB", "mint χADA"],
            ["xadareturn", "χADA → ADA", "burn · release ADA"],
            ["reverse", "Unwind χCKB", "burn · release CKB"],
          ].map(([d, label, subLabel]) => (
            <div key={d} role="button" tabIndex={0} aria-pressed={dir === d} aria-label={`${label} (${subLabel})`}
              style={pill(dir === d)} onClick={() => setDir(d)}
              onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); setDir(d); } }}>
              {label}<span style={sub(dir === d)}>{subLabel}</span>
            </div>
          ))}
        </div>
        {dir === "forward" && <Forward signer={signer} cardano={cardano} cfg={cfg} onLock={setReceiptTx} />}
        {dir === "ada2ckb" && <ForwardAda signer={signer} cardano={cardano} cfg={cfg} xcfg={xcfg} />}
        {dir === "xadareturn" && <ReturnAda signer={signer} cardano={cardano} xcfg={xcfg} />}
        {dir === "reverse" && <Reverse signer={signer} cardano={cardano} cfg={cfg} receiptTx={receiptTx} />}
      </div>
      {tour && <GuidedTour onClose={() => setTour(false)} />}
    </div>
  );
}

export default function App() {
  return (
    <ccc.Provider name="Chiral" defaultClient={ckbClient}>
      <LeapApp />
    </ccc.Provider>
  );
}
