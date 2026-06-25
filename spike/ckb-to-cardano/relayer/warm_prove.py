#!/usr/bin/env python3
"""warm_prove.py - client for the resident leap_bound_windowed prover (CHIRAL_SERVE).

The cold prover reloads the ~480 MB ceremony key every invocation (~5 min). The warm service loads it ONCE and
proves over a unix socket; this client sends one prove request and writes the redeemer to <out>.

  warm_prove.py up   [--sock S]                                  # is the service ready? prints {ok,ready} or exits 1
  warm_prove.py prove <wit> <bridge> <out> [--window W] [--depth 6] [--k 12] [--kmin 12] [--sock S]

Exit 0 + prints the service reply on success; exit 1 on any failure (so the orchestrator can fall back to cold).
"""
import socket, json, sys, os, time

def call(sock, payload, timeout=1800):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.settimeout(timeout)
    s.connect(sock)
    s.sendall((payload if isinstance(payload, str) else json.dumps(payload)).encode() + b"\n")
    buf = b""
    while not buf.endswith(b"\n"):
        d = s.recv(65536)
        if not d:
            break
        buf += d
    s.close()
    return buf.decode().strip()

def opt(args, name, default=None):
    return args[args.index(name) + 1] if name in args else default

def main():
    a = sys.argv[1:]
    sock = opt(a, "--sock", "/tmp/chiral_warm.sock")
    if not a:
        print(__doc__); sys.exit(2)
    if not os.path.exists(sock):
        print(json.dumps({"error": "warm prover socket not present: " + sock})); sys.exit(1)
    if a[0] == "up":
        try:
            print(call(sock, "ping", 10)); sys.exit(0)
        except Exception as e:
            print(json.dumps({"error": "ping failed: " + str(e)})); sys.exit(1)
    if a[0] == "prove":
        wit, bridge, out = a[1], a[2], a[3]
        req = {"wit": wit, "bridge": bridge, "out": out,
               "depth": int(opt(a, "--depth", "6")), "k": int(opt(a, "--k", "12")), "kmin": int(opt(a, "--kmin", "12"))}
        w = opt(a, "--window")
        if w:
            req["window"] = w
        t = time.time()
        try:
            r = call(sock, req)
        except Exception as e:
            print(json.dumps({"error": "prove call failed: " + str(e)})); sys.exit(1)
        try:
            j = json.loads(r)
        except Exception:
            print(json.dumps({"error": "bad reply: " + r[:200]})); sys.exit(1)
        if j.get("error"):
            print(json.dumps(j)); sys.exit(1)
        print(json.dumps({"ok": True, "out": j.get("out"), "round_trip_s": round(time.time() - t, 1), "prove_secs": j.get("prove_secs")}))
        sys.exit(0)
    print(__doc__); sys.exit(2)

if __name__ == "__main__":
    main()
