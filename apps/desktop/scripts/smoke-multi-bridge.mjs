/** Two independent signed bridge descriptors; 2/2 quorum is required to retain write authority. */
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { fork } from "node:child_process";
import { createHmac } from "node:crypto";
import { WebSocket } from "ws";
import { createIdentity } from "@janjacord/identity";
import { canonicalJson, ed25519Fingerprint, ed25519PublicKey, sha256Hex } from "@janjacord/crypto";
import { createSignedBridgeDescriptor } from "@janjacord/protocol";
import { HostClient } from "@janjacord/networking";
import { mintPairingToken } from "./pairing-fixture.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const hostMain = join(__dirname, "..", "..", "janjanode", "dist", "main.js");
const bridgeMain = join(__dirname, "..", "..", "rendezvous", "dist", "main.js");
const bridgePorts = [8980, 8981];
const hostPort = 8982;
const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const waitResult = (client, timeoutMs = 5_000) => new Promise((resolve) => {
  client.onEventOnce("result", (frame) => resolve(frame.data));
  setTimeout(() => resolve(null), timeoutMs);
});

function descriptor(port, seed) {
  const now = Date.now();
  const publicKey = ed25519PublicKey(seed);
  return createSignedBridgeDescriptor({
    version: 1,
    bridgeId: ed25519Fingerprint(publicKey),
    endpoints: [`wss://127.0.0.1:${port}`],
    issuedAt: now,
    expiresAt: now + 60_000,
  }, seed);
}

function spawnBridge(port) {
  return fork(bridgeMain, [], {
    env: { ...process.env, JC_RENDEZVOUS_PORT: String(port) },
    stdio: ["ignore", "pipe", "pipe", "ipc"],
    execPath: process.env.JC_NODE_BIN ?? "node",
  });
}

async function resolve(port, serverId, authorityFingerprint) {
  try {
    const ws = new WebSocket(`ws://127.0.0.1:${port}/rendezvous`);
    await new Promise((resolveOpen, reject) => {
      const timer = setTimeout(() => reject(new Error("open timeout")), 1_500);
      ws.once("open", () => { clearTimeout(timer); resolveOpen(); });
      ws.once("error", reject);
    });
    const response = await new Promise((resolveResponse) => {
      const timer = setTimeout(() => resolveResponse(null), 1_500);
      ws.once("message", (raw) => { clearTimeout(timer); resolveResponse(JSON.parse(raw.toString())); });
      ws.send(JSON.stringify({ type: "resolve", serverId, authorityFingerprint }));
    });
    ws.close();
    return response;
  } catch {
    return null;
  }
}

async function pollResolve(port, serverId, authorityFingerprint, timeoutMs = 8_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const result = await resolve(port, serverId, authorityFingerprint);
    if (result?.ok) return result;
    await wait(250);
  }
  throw new Error(`bridge ${port} did not resolve host`);
}

async function main() {
  const dir = mkdtempSync(join(tmpdir(), "jc-multi-bridge-"));
  const bridges = [];
  let host;
  try {
    const turnSecret = "multi-bridge-turn-secret-that-never-leaves-the-bridge";
    const turnSecretPath = join(dir, "turn-secret");
    writeFileSync(turnSecretPath, `${turnSecret}\n`, { mode: 0o600 });
    const owner = await createIdentity("owner", "owner-password-123", join(dir, "owner.vault"));
    const authoritySeed = createHmac("sha256", owner.seed).update("authority").digest();
    const hostSeed = createHmac("sha256", owner.seed).update("primary-host").digest();
    const bridgeSeeds = [Buffer.alloc(32, 31), Buffer.alloc(32, 32)];
    const descriptors = bridgePorts.map((port, index) => descriptor(port, bridgeSeeds[index]));
    const bridgePairings = descriptors.map((entry, index) => {
      const adminKey = `multi-bridge-pairing-admin-key-${index}-0123456789abcdef`;
      const adminKeyPath = join(dir, `bridge-${index}-pairing-admin-key`);
      writeFileSync(adminKeyPath, `${adminKey}\n`, { mode: 0o600 });
      const bridge = fork(bridgeMain, [], {
        env: {
          ...process.env,
          JC_RENDEZVOUS_PORT: String(bridgePorts[index]),
          JC_TURN_SHARED_SECRET_FILE: turnSecretPath,
          JC_BRIDGE_PAIRING_ADMIN_KEY_FILE: adminKeyPath,
          JC_BRIDGE_DOMAIN: "127.0.0.1",
        },
        stdio: ["ignore", "pipe", "pipe", "ipc"],
        execPath: process.env.JC_NODE_BIN ?? "node",
      });
      bridges.push(bridge);
      return { bridgeId: entry.payload.bridgeId, pairingToken: mintPairingToken(entry.payload.bridgeId, adminKey) };
    });
    await wait(900);

    host = fork(hostMain, [], {
      env: {
        ...process.env,
        JC_DB_KEY: owner.dbKey.toString("hex"),
        JC_DB_PATH: join(dir, "server.db"),
        JC_OWNER_IDENTITY: owner.identityId,
        JC_OWNER_NICKNAME: owner.nickname,
        JC_OWNER_PUBLIC_KEY: ed25519PublicKey(owner.seed).toString("base64url"),
        JC_AUTHORITY_SIGNING_SEED: authoritySeed.toString("hex"),
        JC_HOST_SIGNING_SEED: hostSeed.toString("hex"),
        JC_SERVER_NAME: "Multi Bridge",
        JC_PORT: String(hostPort),
        JC_BRIDGE_DESCRIPTORS: JSON.stringify(descriptors),
        JC_BRIDGE_PAIRINGS: JSON.stringify(bridgePairings),
        JC_ALLOW_INSECURE_BRIDGE_LOOPBACK: "1",
        JC_RENDEZVOUS_RENEW_MS: "3000",
        JC_PRIMARY_FENCE_MS: "5000",
      },
      stdio: ["ignore", "pipe", "pipe", "ipc"],
      execPath: process.env.JC_NODE_BIN ?? "node",
    });
    host.stderr?.on("data", (data) => process.stderr.write(data));
    await wait(1_500);
    const authorityFingerprint = ed25519Fingerprint(ed25519PublicKey(authoritySeed));
    const client = new HostClient(`ws://127.0.0.1:${hostPort}/signal`, {
      identityId: owner.identityId,
      deviceSeed: owner.seed,
      authorityFingerprint,
      expectedHostPublicKey: ed25519PublicKey(hostSeed).toString("base64url"),
    });
    await new Promise((resolveOpen, reject) => {
      const timer = setTimeout(() => reject(new Error("host auth timeout")), 5_000);
      client.onOpen(() => { clearTimeout(timer); resolveOpen(); });
    });
    const statePromise = new Promise((resolveState) => client.onEventOnce("result", (frame) => resolveState(frame.data)));
    client.send("hello", { identityId: owner.identityId });
    const state = await statePromise;
    if (!state?.ok) throw new Error("host state unavailable");
    const serverId = state.data.serverId;

    let ice = null;
    const iceDeadline = Date.now() + 5_000;
    while (Date.now() < iceDeadline) {
      const resultPromise = waitResult(client);
      client.send("command", { type: "connectivity.iceConfig" });
      ice = await resultPromise;
      if (ice?.ok) break;
      await wait(200);
    }
    if (!ice?.ok || !Array.isArray(ice.data.iceServers) || !ice.data.iceServers.some((server) => {
      const urls = Array.isArray(server.urls) ? server.urls : [server.urls];
      return urls.some((value) => value.startsWith("turn:"));
    })) throw new Error(`owner received no temporary TURN configuration: ${JSON.stringify(ice)}`);
    if (JSON.stringify(ice).includes(turnSecret) || ice.data.expiresAt <= Date.now()) {
      throw new Error("ICE command exposed issuer secret or stale credentials");
    }

    const first = await pollResolve(bridgePorts[0], serverId, authorityFingerprint);
    const second = await pollResolve(bridgePorts[1], serverId, authorityFingerprint);
    const record1a = first.data.records[0].record;
    const record1b = second.data.records[0].record;
    const hash1a = sha256Hex(canonicalJson(record1a));
    const hash1b = sha256Hex(canonicalJson(record1b));
    if (record1a.payload.recordSeq !== 1 || record1b.payload.recordSeq !== 1 || hash1a !== hash1b) {
      throw new Error("bridges did not receive byte-identical seq1 checkpoints");
    }
    const expectedEndpoints = bridgePorts.map((port) => `wss://127.0.0.1:${port}/signaling`).sort();
    if (JSON.stringify([...record1a.payload.endpoints].sort()) !== JSON.stringify(expectedEndpoints)) {
      throw new Error("shared record does not announce all signaling endpoints");
    }
    if (bridgePairings.some(({ pairingToken }) => canonicalJson(record1a).includes(pairingToken))
      || canonicalJson(record1a).includes(turnSecret)) {
      throw new Error("signed record leaked pairing or TURN shared secret");
    }

    await wait(3_300);
    const renewedFirst = await pollResolve(bridgePorts[0], serverId, authorityFingerprint);
    const renewedSecond = await pollResolve(bridgePorts[1], serverId, authorityFingerprint);
    const record2a = renewedFirst.data.records[0].record;
    const record2b = renewedSecond.data.records[0].record;
    if (record2a.payload.recordSeq !== 2 || sha256Hex(canonicalJson(record2a)) !== sha256Hex(canonicalJson(record2b))
      || record2a.payload.previousRecordHash !== hash1a) throw new Error("seq2 chain diverged between bridges");

    const writeWithStrictQuorum = waitResult(client);
    client.send("command", { type: "channel.create", channelType: "text", name: "strict-quorum-writer" });
    const quorumWriteResult = await writeWithStrictQuorum;
    if (!quorumWriteResult?.ok) {
      throw new Error(`primary rejected a write despite 2/2 live bridge quorum: ${JSON.stringify(quorumWriteResult)}`);
    }

    bridges[0].kill();
    await wait(6_500);
    const surviving = await pollResolve(bridgePorts[1], serverId, authorityFingerprint);
    const seqAfter = surviving.data.records[0].record.payload.recordSeq;
    if (seqAfter <= 2) throw new Error("surviving bridge did not receive a renewed record");
    const failoverIcePromise = waitResult(client);
    client.send("command", { type: "connectivity.iceConfig" });
    const failoverIce = await failoverIcePromise;
    if (!failoverIce?.ok || failoverIce.data.iceServers.length === 0) {
      throw new Error("owner lost ICE config when one bridge failed");
    }
    const writeAfterBridgeLoss = waitResult(client);
    client.send("command", { type: "channel.create", channelType: "text", name: "bridge-loss-survivor" });
    const writeResult = await writeAfterBridgeLoss;
    if (writeResult?.ok || writeResult?.error?.code !== "conflict") {
      throw new Error(`primary retained write authority without 2/2 live bridge quorum: ${JSON.stringify(writeResult)}`);
    }
    console.log("[smoke-multi-bridge] TWO BRIDGES + ICE + 2/2 WRITE QUORUM + MINORITY SELF-FENCE OK");
    client.close();
  } finally {
    host?.kill();
    for (const bridge of bridges) bridge?.kill();
    rmSync(dir, { recursive: true, force: true });
  }
}

main().catch((error) => { console.error("[smoke-multi-bridge]", error); process.exitCode = 1; });
