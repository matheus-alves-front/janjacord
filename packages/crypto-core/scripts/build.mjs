// Build do MLS → WASM. Se o pkg já está versionado, pula o wasm-pack (não precisa de Rust —
// essencial para Windows/sem toolchain). Force rebuild com JC_REBUILD_WASM=1.
import { existsSync } from "node:fs";
import { spawnSync } from "node:child_process";

const wasmFile = "pkg/janjacord_mls_bg.wasm";
if (existsSync(wasmFile) && process.env.JC_REBUILD_WASM !== "1") {
  console.log("[crypto-core] wasm já buildado (pkg versionado) — pulando wasm-pack");
  process.exit(0);
}
console.log("[crypto-core] compilando MLS → WASM (requer Rust + wasm-pack)…");
const r = spawnSync("wasm-pack", ["build", "--target", "nodejs", "--release"], {
  stdio: "inherit",
  shell: process.platform === "win32",
});
process.exit(r.status ?? 1);
