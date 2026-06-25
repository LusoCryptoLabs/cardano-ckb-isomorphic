// _rt.mjs - runtime portability for the relayer pipeline. The python steps + prover ELFs run either:
//   * on THIS dev box (Windows host + the WSL distro "ChiralSP1"): via `wsl.exe -d ChiralSP1 bash -lc …`, or
//   * on a Linux VPS (the prover ELFs are Linux binaries - they run natively, no WSL): via `bash -lc …`.
// One toggle + one repo-path constant drive both. The Windows+WSL behaviour is the DEFAULT (unchanged on this
// machine); a Linux host auto-selects native, and the deploy sets CHIRAL_REPO_SH explicitly.
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));            // relayer/onchain

// native (no WSL) when explicitly asked OR whenever we're not on Windows (a Linux VPS).
export const NATIVE = process.env.CHIRAL_NATIVE === "1" || process.platform !== "win32";
export const WSL_DISTRO = process.env.WSL_DISTRO || "ChiralSP1";

// the repo path as the SHELL / python / provers see it. Native: the real repo dir (node and bash share the FS).
// WSL: the /mnt mount of the Windows checkout. Override with CHIRAL_REPO_SH (the deploy sets it on the VPS).
export const REPO_SH = process.env.CHIRAL_REPO_SH || (NATIVE ? path.resolve(HERE, "..", "..") : "/mnt/d/App - Chiral");

// [command, args] to run a bash pipeline string in the right environment. Pass to spawn()/execFileSync().
export function shInvoke(script) {
  return NATIVE ? ["bash", ["-lc", script]] : ["wsl.exe", ["-d", WSL_DISTRO, "bash", "-lc", script]];
}
