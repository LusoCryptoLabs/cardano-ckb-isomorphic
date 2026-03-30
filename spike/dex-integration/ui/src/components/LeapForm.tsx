import { useMemo, useState } from "react";
import { TOKEN } from "../config";
import { toBaseUnits, fromBaseUnits } from "../lib/amount";
import { GuardPolicy, OPEN_POLICY, checkPolicy, Direction } from "../lib/policy";

/** The leap action form. Validates amount against decimals + the live caps/pause policy BEFORE building a
 *  tx (the on-chain guard is still the authority). `onSubmit` receives the validated base-units amount. */
export function LeapForm({
  policy,
  canSubmit,
  onSubmit,
}: {
  policy: GuardPolicy | null;
  canSubmit: boolean;
  onSubmit: (dir: Direction, baseUnits: bigint) => void;
}) {
  const [dir, setDir] = useState<Direction>("in");
  const [display, setDisplay] = useState("");
  const p = policy ?? OPEN_POLICY;

  const parsed = useMemo(() => {
    if (display.trim() === "") return { base: null as bigint | null, err: null as string | null };
    try {
      return { base: toBaseUnits(display), err: null };
    } catch (e) {
      return { base: null, err: (e as Error).message };
    }
  }, [display]);

  const policyErr = parsed.base !== null ? checkPolicy(p, dir, parsed.base) : null;
  const blocked = parsed.base === null || parsed.base === 0n || !!policyErr;

  return (
    <div className="leap">
      <div className="dir-toggle">
        <button className={dir === "in" ? "on" : ""} onClick={() => setDir("in")}>
          Leap in → mint
        </button>
        <button className={dir === "out" ? "on" : ""} onClick={() => setDir("out")}>
          Leap out → burn
        </button>
      </div>

      <label className="amount-field">
        <span>Amount ({TOKEN.symbol}, {TOKEN.decimals} dp)</span>
        <input
          inputMode="decimal"
          placeholder={`0.${"0".repeat(Math.min(2, TOKEN.decimals))}`}
          value={display}
          onChange={(e) => setDisplay(e.target.value)}
        />
      </label>

      <div className="hints">
        {parsed.err && <span className="err">{parsed.err}</span>}
        {parsed.base !== null && !parsed.err && (
          <span className="ok">= {parsed.base.toString()} base units</span>
        )}
        {policyErr && <span className="err">{policyErr}</span>}
      </div>

      <button className="primary" disabled={blocked || !canSubmit} onClick={() => onSubmit(dir, parsed.base!)}>
        {dir === "in" ? "Mint to my account" : "Burn & release"}
      </button>
      {!canSubmit && (
        <p className="note">
          Configure the deployed hashes in <code>config.ts</code> and connect the matching wallet to enable
          submission. Amount validation + caps/pause checks are live regardless.
        </p>
      )}
      {p.maxAmount !== 0n && (
        <p className="note">Per-leap cap: {fromBaseUnits(p.maxAmount)} {TOKEN.symbol}.</p>
      )}
    </div>
  );
}
