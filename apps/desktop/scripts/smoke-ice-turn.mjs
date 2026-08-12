import { fork, spawn, spawnSync } from "node:child_process";
import { createHmac, randomBytes, randomUUID } from "node:crypto";
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createConnection } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { createIdentity } from "@janjacord/identity";
import {
  decryptAsset,
  ed25519Fingerprint,
  ed25519PublicKey,
  encryptAsset,
  newAssetKey,
  sha256Hex,
} from "@janjacord/crypto";
import {
  attachmentSha256,
  buildEnvelope,
  createSignedBridgeDescriptor,
  decodeAttachmentChunk,
  encodeAttachmentChunks,
  parseInviteV3,
} from "@janjacord/protocol";
import * as mls from "@janjacord/crypto-core";
import { HostClient, IceHostTransport, verifyHostAuthenticationContext } from "@janjacord/networking";
import { WebSocket } from "ws";
import { mintPairingToken } from "./pairing-fixture.mjs";

const root = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const bridgeMain = join(root, "rendezvous", "dist", "main.js");
const hostMain = join(root, "janjanode", "dist", "main.js");
const bridgePort = 8994;
const hostPort = 8995;
const turnPort = 34791;
const dockerName = `jc-ice-turn-${process.pid}`;
const resources = {
  dir: null,
  coturn: null,
  bridge: null,
  host: null,
  local: null,
  ice: null,
  bobIce: null,
  unauthorizedIce: null,
};
let cleanupPromise = null;

const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const waitResult = (client, timeoutMs = 8_000) => new Promise((resolve) => {
  let settled = false;
  const timer = setTimeout(() => {
    if (settled) return;
    settled = true;
    resolve(null);
  }, timeoutMs);
  client.onEventOnce("result", (frame) => {
    if (settled) return;
    settled = true;
    clearTimeout(timer);
    resolve(frame.data);
  });
});

function withTimeout(promise, timeoutMs, message) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(message)), timeoutMs);
    promise.then(
      (value) => { clearTimeout(timer); resolve(value); },
      (error) => { clearTimeout(timer); reject(error); },
    );
  });
}

async function terminateChild(child) {
  if (!child || child.exitCode !== null || child.signalCode !== null) return;
  const exited = new Promise((resolve) => child.once("exit", resolve));
  child.kill("SIGTERM");
  await Promise.race([exited, wait(2_000)]);
  if (child.exitCode === null && child.signalCode === null) {
    child.kill("SIGKILL");
    await Promise.race([exited, wait(2_000)]);
  }
}

function cleanup() {
  if (cleanupPromise) return cleanupPromise;
  cleanupPromise = (async () => {
    try { resources.bobIce?.close(); } catch { /* already closed */ }
    try { resources.unauthorizedIce?.close(); } catch { /* already closed */ }
    try { resources.ice?.close(); } catch { /* already closed */ }
    try { resources.local?.close(); } catch { /* already closed */ }
    await Promise.all([terminateChild(resources.host), terminateChild(resources.bridge)]);
    spawnSync("docker", ["rm", "-f", dockerName], { stdio: "ignore" });
    await terminateChild(resources.coturn);
    if (resources.dir) rmSync(resources.dir, { recursive: true, force: true });
  })();
  return cleanupPromise;
}

async function waitTcp(host, port, timeoutMs = 10_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const connected = await new Promise((resolve) => {
      const socket = createConnection({ host, port });
      socket.once("connect", () => { socket.destroy(); resolve(true); });
      socket.once("error", () => resolve(false));
      socket.setTimeout(300, () => { socket.destroy(); resolve(false); });
    });
    if (connected) return;
    await wait(150);
  }
  throw new Error("coturn did not become reachable");
}

async function waitContainerAddress(name, timeoutMs = 10_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const inspected = spawnSync("docker", [
      "inspect", "--format", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", name,
    ], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] });
    const address = inspected.status === 0 ? inspected.stdout.trim() : "";
    if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(address)) return address;
    await wait(100);
  }
  throw new Error("coturn container did not receive a bridge address");
}

async function waitCandidatePair(ice, timeoutMs = 5_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const pair = ice.diagnostics().selectedCandidatePair;
    if (pair) return pair;
    await wait(100);
  }
  return null;
}

async function assertRelayTransport(ice, label) {
  const pair = await waitCandidatePair(ice);
  if (!pair || pair.local.type.toLowerCase() !== "relay" || pair.remote.type.toLowerCase() !== "relay") {
    throw new Error(`${label} selected a non-relay pair: ${JSON.stringify(pair)}`);
  }
  const rtc = ice.rtcIceConfiguration();
  if (!rtc || rtc.iceTransportPolicy !== "relay" || rtc.iceServers.some((server) => {
    const urls = Array.isArray(server.urls) ? server.urls : [server.urls];
    return urls.some((url) => url.startsWith("stun:"));
  })) throw new Error(`${label} call configuration leaked STUN/direct candidates`);
  return pair;
}

function waitDomainEvent(transport, predicate, timeoutMs = 8_000) {
  return withTimeout(new Promise((resolve) => {
    transport.onEvent((event) => {
      if (predicate(event)) {
        transport.onEvent(() => {});
        resolve(event);
      }
    });
  }), timeoutMs, "domain event timeout");
}

async function resolveHost(serverId, authorityFingerprint) {
  const ws = new WebSocket(`ws://127.0.0.1:${bridgePort}/rendezvous`);
  try {
    await withTimeout(new Promise((resolve, reject) => { ws.on("open", resolve); ws.on("error", reject); }), 5_000, "bridge resolve connection timeout");
    return await withTimeout(new Promise((resolve) => {
      ws.once("message", (raw) => resolve(JSON.parse(raw.toString())));
      ws.send(JSON.stringify({ type: "resolve", serverId, authorityFingerprint }));
    }), 5_000, "bridge resolve timeout");
  } finally {
    ws.close();
  }
}

async function main() {
  const dir = mkdtempSync(join(tmpdir(), "jc-ice-turn-"));
  resources.dir = dir;
  const secretPath = join(dir, "turn-secret");
  const pairingAdminKeyPath = join(dir, "pairing-admin-key");
  const configPath = join(dir, "turnserver.conf");
  const sharedSecret = randomBytes(32).toString("base64url");
  const pairingAdminKey = randomBytes(32).toString("base64url");
  writeFileSync(secretPath, `${sharedSecret}\n`, { mode: 0o600 });
  writeFileSync(pairingAdminKeyPath, `${pairingAdminKey}\n`, { mode: 0o600 });
  writeFileSync(configPath, [
    `listening-port=${turnPort}`,
    "realm=localhost",
    "fingerprint",
    "use-auth-secret",
    `static-auth-secret=${sharedSecret}`,
    "min-port=49320",
    "max-port=49339",
    "no-multicast-peers",
    "no-tls",
    "no-dtls",
    "simple-log",
  ].join("\n") + "\n", { mode: 0o600 });
  chmodSync(configPath, 0o600);
  // The secret only exists in mode-0600 temp files mounted read-only; it is never an argv/env/log value.
  const coturn = spawn("docker", [
    "run", "--rm", "--name", dockerName,
    "--user", `${process.getuid()}:${process.getgid()}`,
    "--mount", `type=bind,src=${configPath},dst=/etc/coturn/turnserver.conf,readonly`,
    "coturn/coturn:4.15.0-r0", "-c", "/etc/coturn/turnserver.conf", "--log-file=stdout",
  ], { stdio: ["ignore", "pipe", "pipe"] });
  resources.coturn = coturn;
  let coturnError = "";
  const captureCoturn = (chunk) => {
    const line = chunk.toString();
    if (!line.includes(sharedSecret)) coturnError = `${coturnError}${line}`.slice(-4_000);
  };
  coturn.stdout.on("data", captureCoturn);
  coturn.stderr.on("data", captureCoturn);
  coturn.on("error", (error) => captureCoturn(Buffer.from(error.message)));
  let bridge;
  let host;
  try {
    const relayAddress = await waitContainerAddress(dockerName);
    await waitTcp(relayAddress, turnPort);
    const owner = await createIdentity("owner", "password-123", join(dir, "owner.json"));
    const bob = await createIdentity("bob", "password-456", join(dir, "bob.json"));
    await mls.default;
    const authoritySeed = createHmac("sha256", owner.seed).update("janjacord-authority-signing-v1").digest();
    const hostSeed = createHmac("sha256", owner.seed).update("janjacord-host-signing-v1").digest();
    const bridgeSeed = Buffer.alloc(32, 63);
    const bridgeDescriptor = createSignedBridgeDescriptor({
      version: 1,
      bridgeId: ed25519Fingerprint(ed25519PublicKey(bridgeSeed)),
      endpoints: [`wss://127.0.0.1:${bridgePort}`],
      issuedAt: Date.now(),
      expiresAt: Date.now() + 120_000,
    }, bridgeSeed);
    const pairingToken = mintPairingToken(bridgeDescriptor.payload.bridgeId, pairingAdminKey);
    const child = { stdio: ["ignore", "pipe", "pipe", "ipc"], execArgv: [] };
    bridge = fork(bridgeMain, [], {
      ...child,
      env: {
        ...process.env,
        JC_RENDEZVOUS_PORT: String(bridgePort),
        JC_TURN_SHARED_SECRET_FILE: secretPath,
        JC_BRIDGE_PAIRING_ADMIN_KEY_FILE: pairingAdminKeyPath,
        JC_BRIDGE_DOMAIN: relayAddress,
        JC_TURN_PORT: String(turnPort),
        JC_TURN_TLS_PORT: "53499",
      },
    });
    resources.bridge = bridge;
    bridge.stdout?.on("data", (data) => process.stdout.write(data));
    bridge.stderr?.on("data", (data) => process.stderr.write(data));
    await wait(700);

    host = fork(hostMain, [], {
      ...child,
      env: {
        ...process.env,
        JC_DB_KEY: owner.dbKey.toString("hex"),
        JC_DB_PATH: join(dir, "server.db"),
        JC_OWNER_IDENTITY: owner.identityId,
        JC_OWNER_NICKNAME: owner.nickname,
        JC_OWNER_PUBLIC_KEY: ed25519PublicKey(owner.seed).toString("base64url"),
        JC_AUTHORITY_SIGNING_SEED: authoritySeed.toString("hex"),
        JC_HOST_SIGNING_SEED: hostSeed.toString("hex"),
        JC_SERVER_NAME: "ICE TURN Smoke",
        JC_PORT: String(hostPort),
        JC_BRIDGE_DESCRIPTORS: JSON.stringify([bridgeDescriptor]),
        JC_BRIDGE_PAIRINGS: JSON.stringify([{ bridgeId: bridgeDescriptor.payload.bridgeId, pairingToken }]),
        JC_ALLOW_INSECURE_BRIDGE_LOOPBACK: "1",
      },
    });
    resources.host = host;
    host.stdout?.on("data", (data) => process.stdout.write(data));
    host.stderr?.on("data", (data) => process.stderr.write(data));
    await wait(1_800);

    const authority = ed25519Fingerprint(ed25519PublicKey(authoritySeed));
    const local = new HostClient(`ws://127.0.0.1:${hostPort}/signal`, {
      identityId: owner.identityId,
      deviceSeed: owner.seed,
      authorityFingerprint: authority,
      expectedHostPublicKey: ed25519PublicKey(hostSeed).toString("base64url"),
    });
    resources.local = local;
    await withTimeout(new Promise((resolve) => local.onOpen(resolve)), 5_000, "local auth timeout");
    let resultPromise = waitResult(local);
    local.send("hello", { identityId: owner.identityId });
    const state = await resultPromise;
    if (!state?.ok) throw new Error(`local state failed: ${JSON.stringify(state)}`);

    const resolved = await resolveHost(state.data.serverId, state.data.authority.fingerprint);
    if (!resolved?.ok) throw new Error(`signed resolve failed: ${JSON.stringify(resolved)}`);
    const registration = resolved.data.registrations?.[0] ?? resolved.data.records?.[0];
    const verified = verifyHostAuthenticationContext(registration, {
      serverId: state.data.serverId,
      authorityFingerprint: state.data.authority.fingerprint,
    });
    if (!verified) throw new Error("resolved host chain failed verification");

    const stranger = await createIdentity("stranger", "stranger-password-123", join(dir, "stranger.vault"));
    let unauthorizedOpened = false;
    let unauthorizedReceivedIce = false;
    const unauthorizedIce = new IceHostTransport({
      bridgeUrls: [`ws://127.0.0.1:${bridgePort}/signaling`],
      serverId: state.data.serverId,
      authorityFingerprint: state.data.authority.fingerprint,
      hostId: verified.hostId,
      hostRegistration: registration,
      identityId: stranger.identityId,
      deviceSeed: stranger.seed,
      iceServers: [],
      networkPrivacy: "relay",
      connectionTimeoutMs: 2_000,
      maxReconnectAttempts: 0,
    });
    resources.unauthorizedIce = unauthorizedIce;
    unauthorizedIce.onOpen(() => { unauthorizedOpened = true; });
    unauthorizedIce.onIceConfiguration(() => { unauthorizedReceivedIce = true; });
    await withTimeout(new Promise((resolve) => unauthorizedIce.onClose(resolve)), 5_000, "unauthorized ICE access was not rejected");
    unauthorizedIce.close();
    if (unauthorizedOpened || unauthorizedReceivedIce) throw new Error("client without membership/invite received ICE/TURN access");
    console.log("[smoke-ice-turn] unauthorized client received no ICE/TURN configuration");

    const ice = new IceHostTransport({
      bridgeUrls: [`ws://127.0.0.1:${bridgePort}/signaling`],
      serverId: state.data.serverId,
      authorityFingerprint: state.data.authority.fingerprint,
      hostId: verified.hostId,
      hostRegistration: registration,
      identityId: owner.identityId,
      deviceSeed: owner.seed,
      iceServers: [],
      networkPrivacy: "relay",
    });
    resources.ice = ice;
    await withTimeout(new Promise((resolve) => ice.onOpen(resolve)), 20_000, "relay-only ICE auth timeout");
    const ownerPair = await assertRelayTransport(ice, "owner");
    resultPromise = waitResult(ice);
    ice.send("hello", { identityId: owner.identityId });
    const relayState = await resultPromise;
    if (!relayState?.ok || relayState.data.serverId !== state.data.serverId) throw new Error("TURN host state mismatch");

    const created = await ice.request({
      type: "channel.create",
      channelType: "text",
      name: `relay-domain-${Date.now().toString(36)}`,
    });
    if (!created?.ok) throw new Error(`relay state mutation failed: ${JSON.stringify(created)}`);
    const mutatedState = await ice.request({ type: "server.state" });
    if (!mutatedState?.ok || !mutatedState.data.channels.some((channel) => channel.id === created.data.id)) {
      throw new Error("relay write was not visible in subsequent server state");
    }

    const invite = await ice.request({ type: "invite.create", initialRoleId: "role-member", maxUses: 1 });
    if (!invite?.ok) throw new Error(`relay invite creation failed: ${JSON.stringify(invite)}`);
    const parsedInvite = parseInviteV3(invite.data.inviteKey);
    if (!parsedInvite) throw new Error("relay invite was not JC3");
    const bobIce = new IceHostTransport({
      bridgeUrls: [`ws://127.0.0.1:${bridgePort}/signaling`],
      serverId: state.data.serverId,
      authorityFingerprint: state.data.authority.fingerprint,
      hostId: verified.hostId,
      hostRegistration: registration,
      identityId: bob.identityId,
      deviceSeed: bob.seed,
      iceServers: [],
      networkPrivacy: "relay",
      inviteAccessHash: sha256Hex(Buffer.from(parsedInvite.payload.inviteSecret, "base64url")),
    });
    resources.bobIce = bobIce;
    await withTimeout(new Promise((resolve) => bobIce.onOpen(resolve)), 20_000, "bob relay-only ICE auth timeout");
    const bobPair = await assertRelayTransport(bobIce, "bob");
    const joined = await bobIce.request({ type: "server.join", inviteKey: invite.data.inviteKey });
    if (!joined?.ok) throw new Error(`relay member join failed: ${JSON.stringify(joined)}`);

    const callChannel = await ice.request({ type: "channel.create", channelType: "call", name: "relay-call" });
    if (!callChannel?.ok) throw new Error(`relay call channel failed: ${JSON.stringify(callChannel)}`);
    const ownerCall = await ice.request({ type: "call.join", channelId: callChannel.data.id });
    const bobCall = await bobIce.request({ type: "call.join", channelId: callChannel.data.id });
    if (!ownerCall?.ok || !bobCall?.ok || !bobCall.data.participants.includes(owner.identityId)) {
      throw new Error("relay call membership did not traverse IceHostTransport");
    }
    const relayedSignal = new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("relay call signal timeout")), 5_000);
      bobIce.onEvent((event) => {
        if (event.type === "call.signal" && event.from === owner.identityId) {
          clearTimeout(timer);
          resolve(event.payload);
        }
      });
    });
    const relayOffer = { type: "offer", sdp: "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n" };
    const signalResult = await ice.request({
      type: "call.signal",
      channelId: callChannel.data.id,
      to: bob.identityId,
      payload: relayOffer,
    });
    if (!signalResult?.ok || JSON.stringify(await relayedSignal) !== JSON.stringify(relayOffer)) {
      throw new Error("call signaling did not relay over TURN-backed IceHostTransport");
    }

    const bobKeyPackage = mls.generate_key_package(bob.seed.toString("hex"), bob.identityId);
    const published = await bobIce.request({ type: "keypackage.upload", keyPackageB64: bobKeyPackage });
    if (!published?.ok) throw new Error(`relay key package upload failed: ${JSON.stringify(published)}`);
    const fetched = await ice.request({ type: "keypackage.get", targetIdentityId: bob.identityId });
    if (!fetched?.ok) throw new Error(`relay key package fetch failed: ${JSON.stringify(fetched)}`);
    const groupId = Buffer.from(created.data.id.replace(/-/g, ""), "hex").toString("hex");
    mls.create_group(owner.seed.toString("hex"), owner.identityId, groupId);
    const added = JSON.parse(mls.add_member(owner.seed.toString("hex"), owner.identityId, groupId, fetched.data.keyPackageB64));
    const welcomePromise = waitDomainEvent(bobIce, (event) => event?.type === "welcome.deliver");
    const welcomeSent = await ice.request({ type: "welcome.push", targetIdentityId: bob.identityId, welcomeB64: added.welcomeB64 });
    if (!welcomeSent?.ok) throw new Error(`relay MLS welcome failed: ${JSON.stringify(welcomeSent)}`);
    const welcome = await welcomePromise;
    mls.join_group(bob.seed.toString("hex"), bob.identityId, welcome.welcomeB64);

    const plaintextAsset = Buffer.concat([
      Buffer.from("JanjaCord relay attachment integrity\0", "utf8"),
      randomBytes(4_096),
    ]);
    const assetKey = newAssetKey();
    const encryptedAsset = encryptAsset(assetKey, plaintextAsset);
    const attachmentChunks = encodeAttachmentChunks(encryptedAsset);
    const assetId = randomUUID();
    const assetHash = sha256Hex(plaintextAsset);
    const uploaded = await ice.request({
      type: "attachment.upload.begin",
      assetId,
      channelId: created.data.id,
      audienceMembers: [owner.identityId, bob.identityId].sort(),
      sizeBytes: encryptedAsset.length,
      totalChunks: attachmentChunks.length,
      hash: attachmentSha256(encryptedAsset),
      ttlHours: 1,
    });
    if (!uploaded?.ok) throw new Error(`relay attachment begin failed: ${JSON.stringify(uploaded)}`);
    for (const chunk of attachmentChunks) {
      const chunkUpload = await ice.request({ type: "attachment.upload.chunk", assetId, ...chunk });
      if (!chunkUpload?.ok) throw new Error(`relay attachment chunk upload failed: ${JSON.stringify(chunkUpload)}`);
    }
    const uploadComplete = await ice.request({ type: "attachment.upload.complete", assetId });
    if (!uploadComplete?.ok) throw new Error(`relay attachment completion failed: ${JSON.stringify(uploadComplete)}`);

    const members = [owner.identityId, bob.identityId].sort();
    const messagePayload = JSON.stringify({
      text: "S3 relay MLS domain smoke",
      attachments: [{
        assetId,
        name: "relay-proof.bin",
        mimeType: "application/octet-stream",
        sizeBytes: plaintextAsset.length,
        totalChunks: attachmentChunks.length,
        hash: assetHash,
      }],
      assetKeys: { [assetId]: assetKey.toString("base64") },
    });
    const encryptedMessage = JSON.parse(mls.encrypt(
      owner.seed.toString("hex"),
      owner.identityId,
      groupId,
      Buffer.from(messagePayload).toString("base64"),
    ));
    const envelope = buildEnvelope({
      serverId: state.data.serverId,
      channelId: created.data.id,
      sender: owner.identityId,
      cryptoEpoch: encryptedMessage.epoch,
      audience: { algo: "sha256", commitment: sha256Hex(members.join("\0")), members },
      ciphertext: encryptedMessage.ciphertextB64,
      attachments: [{
        assetId,
        name: "relay-proof.bin",
        mimeType: "application/octet-stream",
        sizeBytes: plaintextAsset.length,
        totalChunks: attachmentChunks.length,
        hash: assetHash,
      }],
      ordering: { seq: 1 },
    });
    const deliveredPromise = waitDomainEvent(
      bobIce,
      (event) => event?.type === "envelope.deliver" && event.envelope?.messageId === envelope.messageId,
    );
    const sent = await ice.request({ type: "message.send", envelope });
    if (!sent?.ok) throw new Error(`relay MLS envelope send failed: ${JSON.stringify(sent)}`);
    const delivered = await deliveredPromise;
    const decryptedMessage = JSON.parse(mls.decrypt(
      bob.seed.toString("hex"),
      bob.identityId,
      groupId,
      delivered.envelope.ciphertext,
    ));
    const decodedPayload = JSON.parse(Buffer.from(decryptedMessage.plaintextB64, "base64").toString("utf8"));
    if (decodedPayload.text !== "S3 relay MLS domain smoke" || decodedPayload.assetKeys?.[assetId] !== assetKey.toString("base64")) {
      throw new Error("relay-delivered MLS payload failed decryption/integrity checks");
    }
    const pending = await bobIce.request({ type: "message.getPending" });
    if (!pending?.ok || !pending.data.some((item) => item.messageId === envelope.messageId)) {
      throw new Error("relay-delivered message was not present in spool");
    }
    const downloaded = await bobIce.request({ type: "attachment.download", assetId });
    if (!downloaded?.ok || downloaded.data.sizeBytes !== encryptedAsset.length) {
      throw new Error(`relay attachment download failed: ${JSON.stringify(downloaded)}`);
    }
    const downloadedChunks = [];
    for (let index = 0; index < downloaded.data.totalChunks; index += 1) {
      const part = await bobIce.request({ type: "attachment.download.chunk", assetId, index });
      if (!part?.ok) throw new Error(`relay attachment chunk download failed: ${JSON.stringify(part)}`);
      downloadedChunks.push(decodeAttachmentChunk(part.data.data, part.data.sizeBytes, part.data.hash));
    }
    const downloadedCiphertext = Buffer.concat(downloadedChunks, downloaded.data.sizeBytes);
    const recoveredAsset = decryptAsset(Buffer.from(decodedPayload.assetKeys[assetId], "base64"), downloadedCiphertext);
    if (!downloadedCiphertext.equals(encryptedAsset) || !recoveredAsset.equals(plaintextAsset) || sha256Hex(recoveredAsset) !== assetHash) {
      throw new Error("relay attachment ciphertext/plaintext integrity mismatch");
    }
    const ownerAck = await ice.request({ type: "message.ackConsumed", messageId: envelope.messageId });
    const bobAck = await bobIce.request({ type: "message.ackConsumed", messageId: envelope.messageId });
    const afterPurge = await bobIce.request({ type: "message.getPending" });
    if (!ownerAck?.ok || !bobAck?.ok || !afterPurge?.ok || afterPurge.data.some((item) => item.messageId === envelope.messageId)) {
      throw new Error("relay message spool did not purge after all audience acknowledgements");
    }

    console.log(`[smoke-ice-turn] owner-pair=${ownerPair.local.type}/${ownerPair.remote.type} bob-pair=${bobPair.local.type}/${bobPair.remote.type}`);
    console.log("[smoke-ice-turn] REAL COTURN UDP + TEMP CREDS + RELAY-ONLY CALL POLICY + WRITE + REAL MLS/SPOOL + ATTACHMENT INTEGRITY OK");
  } catch (error) {
    if (coturnError.trim()) {
      console.error(`[smoke-ice-turn] coturn diagnostics (secret redacted):\n${coturnError.replaceAll(sharedSecret, "[REDACTED]").trim()}`);
    }
    throw error;
  } finally {
    await cleanup();
  }
}

for (const [signal, exitCode] of [["SIGINT", 130], ["SIGTERM", 143]]) {
  process.once(signal, () => {
    cleanup().finally(() => process.exit(exitCode));
  });
}

main()
  .catch((error) => {
    console.error("[smoke-ice-turn]", error.message);
    process.exitCode = 1;
  })
  .finally(cleanup);
