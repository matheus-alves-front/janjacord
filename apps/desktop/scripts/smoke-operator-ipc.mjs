#!/usr/bin/env node
import { fork, spawn } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { ed25519Fingerprint, ed25519PublicKey } from "@janjacord/crypto";
import { createSignedBridgeDescriptor } from "@janjacord/protocol";
import { mintPairingToken } from "./pairing-fixture.mjs";

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const appDirectory = path.resolve(scriptDirectory, "..");
const electron = path.join(appDirectory, "node_modules", "electron", "dist", "electron");
const packagedExecutable = process.env.JC_OPERATOR_APP_EXECUTABLE;
const bridgeMain = path.resolve(appDirectory, "../rendezvous/dist/main.js");
const bridgeBasePort = Number(process.env.JC_OPERATOR_BRIDGE_BASE_PORT ?? 8998);
if (!Number.isSafeInteger(bridgeBasePort) || bridgeBasePort < 1024 || bridgeBasePort > 65_533) {
  throw new Error("JC_OPERATOR_BRIDGE_BASE_PORT must reserve three valid unprivileged TCP ports");
}
const directory = process.env.JC_OPERATOR_SMOKE_DIR ?? mkdtempSync(path.join(tmpdir(), "jc-operator-ipc-"));
mkdirSync(directory, { recursive: true });
const startedAt = new Date().toISOString();
const children = [];
const bridges = [];

function sha256File(file) {
  return createHash("sha256").update(readFileSync(file)).digest("hex");
}

function startBridge(index) {
  const bridgePort = bridgeBasePort + index;
  const seed = randomBytes(32);
  const publicKey = ed25519PublicKey(seed);
  const bridgeId = ed25519Fingerprint(publicKey);
  const adminKey = randomBytes(32).toString("base64url");
  const adminKeyFile = path.join(directory, `bridge-pairing-admin-key-${index + 1}`);
  writeFileSync(adminKeyFile, `${adminKey}\n`, { mode: 0o600 });
  const now = Date.now();
  const descriptor = createSignedBridgeDescriptor({
    version: 1,
    bridgeId,
    endpoints: [
      `wss://127.0.0.1:${bridgePort}/rendezvous`,
      `wss://127.0.0.1:${bridgePort}/signaling`,
    ],
    issuedAt: now,
    expiresAt: now + 10 * 60_000,
  }, seed);
  const pairingToken = mintPairingToken(bridgeId, adminKey);
  const pairing = {
    schema: "janjacord.bridge-pairing.v1",
    descriptor,
    pairingToken,
    pairingKeyId: `sha256:${createHash("sha256").update(pairingToken).digest("hex")}`,
  };
  const pairingFile = path.join(directory, `bridge-pairing-${index + 1}.json`);
  writeFileSync(pairingFile, JSON.stringify(pairing), { mode: 0o600 });
  const bridge = fork(bridgeMain, [], {
    env: {
      ...process.env,
      JC_RENDEZVOUS_PORT: String(bridgePort),
      JC_BRIDGE_PAIRING_ADMIN_KEY_FILE: adminKeyFile,
    },
    stdio: ["ignore", "pipe", "pipe", "ipc"],
    execArgv: [],
  });
  bridge.stdout?.on("data", (data) => process.stdout.write(data));
  bridge.stderr?.on("data", (data) => process.stderr.write(data));
  bridges.push(bridge);
  return pairingFile;
}

function launch(role, pairingFiles) {
  const home = path.join(directory, `home-${role}`);
  mkdirSync(home, { recursive: true });
  const env = {
    ...process.env,
    JC_OPERATOR_SMOKE_ROLE: role,
    JC_OPERATOR_SMOKE_DIR: directory,
    JC_USERDATA_DIR: path.join(directory, `userdata-${role}`),
    JC_OPERATOR_PAIRING_FILES: JSON.stringify(pairingFiles),
    JC_ALLOW_INSECURE_BRIDGE_LOOPBACK: "1",
    HOME: home,
    ...(packagedExecutable ? { APPIMAGE: path.resolve(packagedExecutable) } : {}),
    ...(role === "member" ? { JC_OPERATOR_ATTACHMENT_SAVE_PATH: path.join(directory, "member-download.txt") } : {}),
    ELECTRON_OZONE_PLATFORM_HINT: "x11",
  };
  delete env.ELECTRON_RUN_AS_NODE;
  delete env.WAYLAND_DISPLAY;
  const executable = packagedExecutable ? path.resolve(packagedExecutable) : electron;
  const args = packagedExecutable
    ? ["--no-sandbox", "--ozone-platform=x11"]
    : [appDirectory, "--no-sandbox", "--ozone-platform=x11"];
  const child = spawn(executable, args, {
    cwd: appDirectory,
    env,
    stdio: ["ignore", "pipe", "pipe"],
  });
  child.stdout.on("data", (data) => process.stdout.write(data));
  child.stderr.on("data", (data) => process.stderr.write(data));
  children.push(child);
  return child;
}

function completion(child, role) {
  return new Promise((resolve, reject) => {
    child.once("error", reject);
    child.once("exit", (code, signal) => {
      if (code === 0 || existsSync(path.join(directory, `${role}.done`))) resolve();
      else reject(new Error(`${role} Electron exited code=${String(code)} signal=${String(signal)}`));
    });
  });
}

async function waitForFile(file, timeoutMs = 60_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (existsSync(file)) return;
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error(`timeout waiting for ${path.basename(file)}`);
}

function terminate(child, timeoutMs = 3_000) {
  if (!child || child.exitCode !== null || child.signalCode !== null) return Promise.resolve();
  return new Promise((resolve) => {
    let settled = false;
    const finish = () => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve();
    };
    const timer = setTimeout(finish, timeoutMs);
    child.once("exit", finish);
    child.kill();
  });
}

try {
  const pairingFiles = [0, 1, 2].map(startBridge);
  await new Promise((resolve) => setTimeout(resolve, 1_200));
  const owner = launch("owner", pairingFiles);
  await waitForFile(path.join(directory, "invite.txt"));
  const member = launch("member", pairingFiles);
  await Promise.all([completion(owner, "owner"), completion(member, "member")]);
  if (!existsSync(path.join(directory, "owner.done")) || !existsSync(path.join(directory, "member.done"))) {
    throw new Error("operator smoke completion markers missing");
  }
  if (!existsSync(path.join(directory, "autostart-atomic.done"))) throw new Error("autostart atomicity marker missing");
  if (!existsSync(path.join(directory, "clipboard-conditional.done"))) throw new Error("clipboard conditional cleanup marker missing");
  if (!existsSync(path.join(directory, "bridge-removal-transitions.done"))) throw new Error("bridge removal transition marker missing");
  const downloaded = path.join(directory, "member-download.txt");
  if (!existsSync(downloaded) || readFileSync(downloaded, "utf8") !== "plaintext-through-real-ipc") {
    throw new Error("operator smoke attachment was not saved as authenticated plaintext");
  }
  const executable = path.resolve(packagedExecutable ?? electron);
  writeFileSync(path.join(directory, "execution-evidence.json"), `${JSON.stringify({
    schema: "janjacord.operator-smoke-evidence.v1",
    startedAt,
    completedAt: new Date().toISOString(),
    packaged: Boolean(packagedExecutable),
    executableName: path.basename(executable),
    executableSha256: sha256File(executable),
    result: "passed",
    checks: {
      ownerCreate: true,
      oneInviteMemberJoin: true,
      consumedInviteRetired: true,
      clipboardConditionalCleanup: true,
      inviteDismissFocusRestoration: true,
      consumedInviteFocusRestoration: true,
      bridgeRemovalThreeToTwo: true,
      bridgeRemovalTwoToOne: true,
      attachmentIntegrity: true,
      autostartAtomicity: true,
    },
  }, null, 2)}\n`, { mode: 0o600 });
  console.log(`[smoke-operator-ipc] REAL ELECTRON IPC + OWNER CREATE + ONE-INVITE MEMBER JOIN OK (${directory})`);
} finally {
  await Promise.all([...children, ...bridges].map((child) => terminate(child)));
  if (!process.env.JC_OPERATOR_SMOKE_DIR) {
    rmSync(directory, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  }
}
