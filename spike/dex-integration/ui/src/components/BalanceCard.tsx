import { ReactNode } from "react";

/** A balance tile for one chain: token amount + a secondary line (CKB reserved / lovelace). */
export function BalanceCard({
  chain,
  symbol,
  token,
  sub,
  status,
  children,
}: {
  chain: string;
  symbol: string;
  token: string | null;
  sub?: ReactNode;
  status: string;
  children?: ReactNode;
}) {
  return (
    <div className="card">
      <div className="card-head">
        <span className="chain">{chain}</span>
        <span className="status">{status}</span>
      </div>
      <div className="balance">
        {token === null ? <span className="dim">-</span> : <strong>{token}</strong>} <span className="sym">{symbol}</span>
      </div>
      {sub && <div className="sub">{sub}</div>}
      <div className="card-actions">{children}</div>
    </div>
  );
}
