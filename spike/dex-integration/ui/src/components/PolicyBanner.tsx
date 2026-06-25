import { GuardPolicy } from "../lib/policy";
import { fromBaseUnits } from "../lib/amount";
import { TOKEN } from "../config";

/** Surfaces the live caps/pause policy: a halt banner + the per-leap limits. */
export function PolicyBanner({ policy, configured }: { policy: GuardPolicy | null; configured: boolean }) {
  if (!configured) {
    return (
      <div className="banner muted">
        Policy cell not configured - caps/pause are <strong>off</strong> in this view. Set
        <code> CKB.policyType</code> in <code>config.ts</code> to read the live limits.
      </div>
    );
  }
  if (!policy) {
    return <div className="banner muted">No policy cell found on-chain (open: no caps, not paused).</div>;
  }
  const halted = policy.pausedGlobal || policy.pausedIn || policy.pausedOut;
  const fmt = (v: bigint) => (v === 0n ? "-" : `${fromBaseUnits(v)} ${TOKEN.symbol}`);
  return (
    <div className={`banner ${policy.pausedGlobal ? "danger" : halted ? "warn" : "ok"}`}>
      <div className="banner-row">
        <span>
          {policy.pausedGlobal
            ? "⛔ Bridge paused (global halt)"
            : policy.pausedIn
            ? "⚠️ Leap-in (mint) paused"
            : policy.pausedOut
            ? "⚠️ Leap-out (burn) paused"
            : "✅ Bridge active"}
        </span>
        <span className="caps">
          per-leap min <strong>{fmt(policy.minAmount)}</strong> · cap{" "}
          <strong>{policy.maxAmount === 0n ? "none" : fmt(policy.maxAmount)}</strong>
        </span>
      </div>
    </div>
  );
}
