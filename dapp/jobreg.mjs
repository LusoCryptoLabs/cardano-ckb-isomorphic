// jobreg.mjs - an idempotent, pollable job registry for the dApp's heavy operations.
//
// prove/release/mint/return are long (seconds→minutes) and either mutate shared on-chain singletons or race
// the ONE relayer key. Keying each run by a STABLE idempotency key (the lock/burn/escrow txid) lets a refresh,
// double-click, or reconnect ATTACH to the in-flight run instead of starting a second pipeline - the #1 source
// of the observed "All inputs are spent" self-collisions. Dedup only ever merges ONE user's own retries (keys
// are their own txids), never two different users. A client that lost its socket re-reads state by key.
//
// Idempotency policy:
//   - in-flight (queued/running)  -> attach to the same run.
//   - a recent SUCCESS            -> replayed (proof artifacts + certified releases are stable).
//   - a NOT-YET-CERTIFIED success ({certified:false}, Mithril still pending) -> NOT cached; the next call re-runs.
//   - a FAILURE                   -> NOT cached; a retry genuinely re-runs.
//
// `now`/`uuid` are injectable so the behavior is deterministically testable.
import { randomUUID } from "node:crypto";

export function createJobRegistry({ ttlMs = 10 * 60_000, now = () => Date.now(), uuid = randomUUID } = {}) {
  const JOBS = new Map();   // "kind:txid" -> job { id, kind, key, state, startedAt, promise, result, error, doneAt }

  const prune = () => { const t = now(); for (const [k, j] of JOBS) if (j.doneAt && t - j.doneAt > ttlMs) JOBS.delete(k); };
  const active = (kind) => [...JOBS.values()].filter((j) => j.kind === kind && (j.state === "queued" || j.state === "running"));

  // a client-facing snapshot; `position` is 0 at the front (running/next up), and 0 once finished.
  function view(j) {
    const position = active(j.kind).indexOf(j);
    return { jobId: j.id, kind: j.kind, state: j.state, position: position < 0 ? 0 : position,
      ...(j.result !== undefined ? { result: j.result } : {}), ...(j.error ? { error: j.error } : {}) };
  }

  // Run `fn` behind `gate`, deduped by `kind`+`key`. Returns the (possibly pre-existing) job; await job.promise.
  function run(kind, key, gate, fn) {
    prune();
    const k = `${kind}:${key}`;
    const cur = JOBS.get(k);
    if (cur && (cur.state === "queued" || cur.state === "running" || cur.state === "done")) return cur;   // attach / replay
    const j = { id: uuid(), kind, key: k, state: "queued", startedAt: now(), result: undefined, error: null, doneAt: 0 };
    j.promise = gate(() => { j.state = "running"; return fn(); }).then(
      (r) => { j.state = "done"; j.result = r; j.doneAt = now(); if (r && r.certified === false) JOBS.delete(k); return r; },
      (e) => { j.state = "error"; j.error = String(e?.message || e); j.doneAt = now(); JOBS.delete(k); throw e; },
    );
    JOBS.set(k, j);
    return j;
  }

  const get = (fullKey) => JOBS.get(fullKey) || null;   // fullKey === "kind:txid"
  const load = (proveConcurrency) => ({
    prove_in_flight_or_queued: active("prove").length, prove_concurrency: proveConcurrency,
    release_busy: active("release").length > 0, xada_busy: active("mint").length > 0, xada_return_busy: active("return").length > 0,
  });

  return { run, get, view, load, _jobs: JOBS };
}
