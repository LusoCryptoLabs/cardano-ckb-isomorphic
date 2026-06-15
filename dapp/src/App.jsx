import { useEffect, useState } from "react";
import { ccc } from "@ckb-ccc/connector-react";
import { listCardanoWallets, connectCardano, shortHex } from "./cardano.js";
import { lockCkb, cardanoRecipientCred } from "./leap.js";

const ckbClient = new ccc.ClientPublicTestnet();

function CkbWallet() {
  const { open, disconnect, wallet } = ccc.useCcc();
  const signer = ccc.useSigner();
  const [addr, setAddr] = useState(null);
  const [bal, setBal] = useState(null);
  const [err, setErr] = useState(null);

  useEffect(() => {
    let alive = true;
    (async () => {
      setErr(null);
      if (!signer) { setAddr(null); setBal(null); return; }
      try {
        const a = await signer.getRecommendedAddress();
        if (alive) setAddr(a);
        const b = await signer.getBalance();
        if (alive) setBal(b);
      } catch (e) { if (alive) setErr(String(e?.message || e)); }
    })();
    return () => { alive = false; };
  }, [signer]);

  return (
    <div className="wallet ckb">
      <div className="chain">Nervos CKB · Pudge testnet</div>
      <h2><span className={"dot " + (signer ? "on" : "")} /> {signer ? (wallet?.name || "Connected") : "Wallet"}</h2>
      {signer ? (
        <>
          <div className="addr mono">{addr ? shortHex(addr, 20, 12) : "…"}</div>
          <div className="bal">{bal != null ? (Number(bal) / 1e8).toLocaleString(undefined, { maximumFractionDigits: 4 }) : "…"} <small>CKB</small></div>
          <div className="row"><button className="disc" onClick={disconnect}>Disconnect</button></div>
        </>
      ) : (
        <div className="row">
          <button className="btn-ckb" onClick={open}>Connect CKB wallet</button>
          <span className="muted">JoyID · MetaMask · UTXO Global · …</span>
        </div>
      )}
      {err && <div className="err">{err}</div>}
    </div>
  );
}

function CardanoWallet({ onChange }) {
  const [conn, setConn] = useState(null);
  const [picking, setPicking] = useState(false);
  const [err, setErr] = useState(null);
  const wallets = listCardanoWallets();

  async function pick(key) {
    setPicking(false); setErr(null);
    try { const c = await connectCardano(key); setConn(c); onChange?.(c); }
    catch (e) { setErr(String(e?.message || e)); }
  }
  function disconnect() { setConn(null); onChange?.(null); }

  return (
    <div className="wallet ada">
      <div className="chain">Cardano · preview testnet</div>
      <h2><span className={"dot " + (conn ? "on" : "")} /> {conn ? conn.name : "Wallet"}</h2>
      {conn ? (
        <>
          <div className="addr mono">{shortHex(conn.addressHex, 16, 10)}</div>
          <div className="bal">{conn.networkId === 1 ? "MAINNET ⚠" : "testnet"} <small>network {conn.networkId}</small></div>
          <div className="row"><button className="disc" onClick={disconnect}>Disconnect</button></div>
        </>
      ) : (
        <div className="row">
          <button className="btn-ada" onClick={() => setPicking(true)} disabled={!wallets.length}>Connect Cardano wallet</button>
          <span className="muted">{wallets.length ? "Lace · Eternl · Nami · …" : "no CIP-30 wallet found"}</span>
        </div>
      )}
      {err && <div className="err">{err}</div>}
      {picking && (
        <div className="picker" onClick={() => setPicking(false)}>
          <div className="box" onClick={(e) => e.stopPropagation()}>
            <h3>Choose a Cardano wallet</h3>
            {wallets.map((w) => (
              <button key={w.key} className="opt" onClick={() => pick(w.key)}>
                {w.icon && <img src={w.icon} alt="" />} {w.name}
              </button>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function LeapFlow({ signer, cardano, cfg }) {
  const [amount, setAmount] = useState("");
  const [busy, setBusy] = useState(false);
  const [lockTx, setLockTx] = useState(null);
  const [err, setErr] = useState(null);

  let recipient = null;
  try { recipient = cardano ? cardanoRecipientCred(cardano.addressHex) : null; } catch { /* bad addr */ }
  const ready = !!signer && !!cardano && !!cfg?.bridgeCodeHash && !!recipient;

  async function doLock() {
    setErr(null); setBusy(true); setLockTx(null);
    try { setLockTx(await lockCkb({ signer, cfg, amountCKB: Number(amount), recipientCred28: recipient })); }
    catch (e) { setErr(String(e?.message || e)); }
    finally { setBusy(false); }
  }

  if (!signer || !cardano) {
    return (
      <div className="flow disabled">
        <h2>Leap · CKB → Cardano (χCKB)</h2>
        <p>Connect both your CKB and Cardano wallets to start a leap.</p>
      </div>
    );
  }
  return (
    <div className="flow leap">
      <h2>Leap · CKB → Cardano (χCKB)</h2>
      <p className="muted">Step 1 of 3 · Lock CKB on Nervos (you sign). Then the relayer proves it, and you mint χCKB to your Cardano address.</p>
      {!cfg?.bridgeCodeHash && <div className="err">bridge not configured (backend has no bridge_lock_v1 deploy). Start the backend: <span className="mono">node dapp/server.mjs</span></div>}
      <div className="lockform">
        <label className="amt">Amount
          <span><input type="number" min={cfg?.minLockCKB || 200} step="1" value={amount} onChange={(e) => setAmount(e.target.value)} placeholder={`min ${cfg?.minLockCKB || 200}`} /> CKB</span>
        </label>
        <div className="recip">→ χCKB to <span className="mono">{recipient ? shortHex(recipient, 12, 8) : "—"}</span> <span className="muted">(your Cardano payment credential)</span></div>
        <button className="btn-ckb" disabled={!ready || busy || !amount} onClick={doLock}>{busy ? "locking…" : "Lock CKB"}</button>
      </div>
      {lockTx && <div className="okmsg">Locked ✓ <a className="mono" href={(cfg.ckbExplorer || "#") + lockTx} target="_blank" rel="noopener">{shortHex(lockTx, 14, 8)}</a> · next: prove + mint (increments 3-4)</div>}
      {err && <div className="err">{err}</div>}
      <div className="note">Demo lock: the receipt sits under your own CKB lock (reclaimable). A secure deployment locks it under <span className="mono">burn_gated_unlock_v2</span> so only a certified χCKB burn can release it.</div>
    </div>
  );
}

function Dapp() {
  const signer = ccc.useSigner();
  const [cardano, setCardano] = useState(null);
  const [cfg, setCfg] = useState(null);

  useEffect(() => { fetch("/api/bridge/config").then((r) => r.json()).then(setCfg).catch(() => setCfg({})); }, []);

  return (
    <>
      <header>
        <h1>Chiral</h1>
        <span className="net">lock CKB → mint χCKB on Cardano · testnet · self-custody</span>
      </header>
      <main>
        <div className="wallets">
          <CkbWallet />
          <CardanoWallet onChange={setCardano} />
        </div>
        <LeapFlow signer={signer} cardano={cardano} cfg={cfg} />
      </main>
      <footer>
        Self-custody: you sign every transaction with your own wallet. The relayer only supplies the cross-chain
        proof, it can never move your funds. Testnet, unaudited, no real value.
      </footer>
    </>
  );
}

export default function App() {
  return (
    <ccc.Provider name="Chiral" defaultClient={ckbClient}>
      <Dapp />
    </ccc.Provider>
  );
}
