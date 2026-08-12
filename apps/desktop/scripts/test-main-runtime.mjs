#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const appDirectory = path.resolve(scriptDirectory, "..");
const mainSource = readFileSync(path.join(appDirectory, "electron", "main.mjs"), "utf8");
if (mainSource.includes("new WebSocket(")) {
  throw new Error("desktop main contains an external WebSocket constructor outside the shared policy");
}
if ((mainSource.match(/createExternalWebSocket\(/g) ?? []).length !== 2) {
  throw new Error("desktop main external WebSocket call sites are not all routed through the shared policy");
}
const electron = path.join(appDirectory, "node_modules", "electron", "dist", "electron");
const userData = mkdtempSync(path.join(tmpdir(), "janjacord-main-self-test-"));
const env = {
  ...process.env,
  JC_DESKTOP_MAIN_SELF_TEST: "1",
  JC_USERDATA_DIR: userData,
  ELECTRON_OZONE_PLATFORM_HINT: "x11",
};
delete env.ELECTRON_RUN_AS_NODE;

try {
  const result = spawnSync(electron, [appDirectory, "--no-sandbox", "--ozone-platform=x11"], {
    cwd: appDirectory,
    env,
    stdio: "inherit",
  });
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error(`desktop main runtime self-test exited with ${result.status ?? 1}`);
} finally {
  rmSync(userData, { recursive: true, force: true });
}
