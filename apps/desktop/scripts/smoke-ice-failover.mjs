import { spawn } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const script = join(dirname(fileURLToPath(import.meta.url)), "smoke-ice-host.mjs");
const child = spawn(process.execPath, [script], {
  env: { ...process.env, JC_SMOKE_ICE_FAILOVER: "1" },
  stdio: "inherit",
});

for (const signal of ["SIGINT", "SIGTERM"]) {
  process.once(signal, () => {
    if (child.exitCode === null && child.signalCode === null) child.kill(signal);
  });
}

child.once("error", (error) => {
  console.error("[smoke-ice-failover]", error.message);
  process.exitCode = 1;
});
child.once("exit", (code, signal) => {
  if (signal) console.error(`[smoke-ice-failover] child terminated by ${signal}`);
  process.exitCode = code ?? (signal === "SIGINT" ? 130 : signal === "SIGTERM" ? 143 : 1);
});
