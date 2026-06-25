// jobreg.test.mjs - deterministic checks of the idempotency state machine. Run: node jobreg.test.mjs
import { createJobRegistry } from "./jobreg.mjs";

let pass = 0, fail = 0;
const ok = (cond, msg) => { if (cond) { pass++; } else { fail++; console.error("FAIL:", msg); } };
// a controllable gate: runs fn but lets the test hold completion via a manual deferral
const passthroughGate = (fn) => Promise.resolve().then(fn);
const deferred = () => { let resolve, reject; const promise = new Promise((res, rej) => { resolve = res; reject = rej; }); return { promise, resolve, reject }; };

// deterministic ids + clock
let seq = 0; const uuid = () => `id${++seq}`;
let clock = 1000; const now = () => clock;

async function main() {
  // 1) concurrent identical keys share ONE run (fn invoked once)
  {
    const reg = createJobRegistry({ now, uuid });
    let calls = 0; const d = deferred();
    const fn = () => { calls++; return d.promise; };
    const a = reg.run("prove", "tx1", passthroughGate, fn);
    const b = reg.run("prove", "tx1", passthroughGate, fn);
    ok(a === b, "1: concurrent same-key returns the SAME job object");
    d.resolve({ proof: "p" });
    await a.promise;
    ok(calls === 1, "1: fn invoked exactly once for two concurrent same-key calls");
  }

  // 2) a recent SUCCESS is replayed (fn NOT re-invoked), and the cached result is returned
  {
    const reg = createJobRegistry({ now, uuid });
    let calls = 0;
    const a = reg.run("prove", "tx2", passthroughGate, () => { calls++; return Promise.resolve({ proof: "P" }); });
    const r1 = await a.promise;
    const b = reg.run("prove", "tx2", passthroughGate, () => { calls++; return Promise.resolve({ proof: "X" }); });
    const r2 = await b.promise;
    ok(calls === 1, "2: a cached success is NOT re-run");
    ok(r2.proof === "P", "2: the replay returns the original result");
    ok(a === b, "2: same job object replayed");
  }

  // 3) a NOT-YET-CERTIFIED result ({certified:false}) is NOT cached - next call re-runs
  {
    const reg = createJobRegistry({ now, uuid });
    let calls = 0;
    const a = reg.run("mint", "esc1", passthroughGate, () => { calls++; return Promise.resolve({ certified: false, status: "wait-certification" }); });
    await a.promise;
    ok(reg.get("mint:esc1") === null, "3: certified:false job is dropped from the registry");
    const b = reg.run("mint", "esc1", passthroughGate, () => { calls++; return Promise.resolve({ certified: true, minted: true }); });
    const r = await b.promise;
    ok(calls === 2, "3: the retry genuinely re-runs after a not-yet-certified result");
    ok(r.certified === true, "3: the re-run can now succeed");
  }

  // 4) a FAILURE is NOT cached - a retry re-runs
  {
    const reg = createJobRegistry({ now, uuid });
    let calls = 0;
    const a = reg.run("return", "b1", passthroughGate, () => { calls++; return Promise.reject(new Error("boom")); });
    await a.promise.catch(() => {});
    ok(reg.get("return:b1") === null, "4: a failed job is dropped");
    const b = reg.run("return", "b1", passthroughGate, () => { calls++; return Promise.resolve({ ok: true }); });
    await b.promise;
    ok(calls === 2, "4: a retry after failure re-runs");
  }

  // 5) different keys / kinds are independent; load + position reflect active work
  {
    const reg = createJobRegistry({ now, uuid });
    const d1 = deferred(), d2 = deferred();
    const a = reg.run("release", "r1", passthroughGate, () => d1.promise);
    const b = reg.run("release", "r2", passthroughGate, () => d2.promise);
    ok(a !== b, "5: different keys -> different jobs");
    await Promise.resolve(); // let the gate flip state to running
    const load = reg.load(2);
    ok(load.release_busy === true, "5: load.release_busy true while a release is in flight");
    ok(load.prove_in_flight_or_queued === 0, "5: unrelated kinds stay zero");
    ok(reg.view(b).position === 1, "5: second active release reports position 1");
    d1.resolve({ ok: 1 }); d2.resolve({ ok: 2 });
    await Promise.all([a.promise, b.promise]);
  }

  // 6) TTL prune: a finished result is re-readable, then pruned after ttl elapses
  {
    const reg = createJobRegistry({ ttlMs: 100, now, uuid });
    clock = 5000;
    const a = reg.run("prove", "tx6", passthroughGate, () => Promise.resolve({ proof: "z" }));
    await a.promise;
    ok(reg.get("prove:tx6") !== null, "6: finished job re-readable within TTL");
    clock = 5000 + 200; // advance past ttl
    reg.run("prove", "tx7", passthroughGate, () => Promise.resolve({ proof: "z2" })); // any run() triggers prune
    ok(reg.get("prove:tx6") === null, "6: finished job pruned after TTL");
  }

  console.log(`\njobreg: ${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
}
main();
