// queue.js - honest backpressure for the shared relayer. The backend serializes heavy ops (one prove at a
// time on the VPS, one release/mint/return at a time) behind in-memory gates, and dedups each by the
// lock/burn/escrow txid (see dapp/jobreg.mjs). These hooks turn that into VISIBLE status so a waiting user
// sees "the relayer is busy, you're in line" instead of an apparent hang.
import { useEffect, useState } from "react";

// Poll /api/health for the relayer's live load + warm state. Returns the parsed health body (or null until
// the first response). /api/health returns 503 when not ready but still carries a JSON body, so we parse
// regardless of status. The probe is 30s-cached server-side, so a 4s client poll is cheap.
export function useRelayLoad(intervalMs = 4000) {
  const [health, setHealth] = useState(null);
  useEffect(() => {
    let live = true;
    const tick = async () => {
      try { const r = await fetch("/api/health"); const j = await r.json(); if (live) setHealth(j); }
      catch { /* keep the last good reading */ }
    };
    tick();
    const id = setInterval(tick, intervalMs);
    return () => { live = false; clearInterval(id); };
  }, [intervalMs]);
  return health;   // { ready, warm, load:{ prove_in_flight_or_queued, prove_concurrency, release_busy, xada_busy, xada_return_busy } }
}

// Poll a single heavy job's state by the txid the client already holds (no jobId needed). `kind` is one of
// prove|release|mint|return; `txid` the lock/burn/escrow tx; `active` gates polling to the in-flight window.
// Returns { state, position } (position 0 = at the front / running) or null when there is no live job.
export function useJobPosition(kind, txid, active) {
  const [info, setInfo] = useState(null);
  useEffect(() => {
    if (!active || !txid) { setInfo(null); return; }
    let live = true;
    const key = `${kind}:${String(txid).replace(/^0x/, "")}`;
    const tick = async () => {
      try {
        const r = await fetch(`/api/job?key=${encodeURIComponent(key)}`);
        if (!live) return;
        setInfo(r.ok ? await r.json() : null);   // 404 -> not (yet) registered / already finished
      } catch { /* keep the last reading */ }
    };
    tick();
    const id = setInterval(tick, 3000);
    return () => { live = false; clearInterval(id); };
  }, [kind, txid, active]);
  return info;   // { jobId, kind, state, position } or null
}

// One-line human summary of the relayer load, or null when idle (so the caller can hide the banner).
export function loadSummary(health) {
  const l = health?.load;
  if (!l) return null;
  const parts = [];
  if (l.prove_in_flight_or_queued > 0) {
    const n = l.prove_in_flight_or_queued, cap = l.prove_concurrency || 1;
    parts.push(n > cap ? `${n} proofs in line (${cap} at a time)` : `${n} proof${n > 1 ? "s" : ""} in flight`);
  }
  if (l.release_busy) parts.push("CKB release running");
  if (l.xada_busy) parts.push("χADA mint running");
  if (l.xada_return_busy) parts.push("χADA return running");
  return parts.length ? parts.join(" · ") : null;
}
