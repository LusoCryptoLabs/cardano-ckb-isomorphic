import { useEffect, useState } from "react";
import { ccc } from "@ckb-ccc/connector-react";
import { listCardanoWallets, connectCardano, shortHex } from "./cardano.js";

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

function Dapp() {
  const signer = ccc.useSigner();
  const [cardano, setCardano] = useState(null);
  const both = !!signer && !!cardano;

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
        <div className={"flow" + (both ? "" : " disabled")}>
          <h2>Leap · CKB → Cardano (χCKB)</h2>
          {both
            ? <p>Both wallets connected. The lock + prove + mint flow lands next (increment 2). You will lock CKB (signed by your CKB wallet) and mint χCKB to your Cardano address (signed by your Cardano wallet).</p>
            : <p>Connect both your CKB and Cardano wallets to start a leap.</p>}
        </div>
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
