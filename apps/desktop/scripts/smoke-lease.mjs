/** Real signed lease: matching health is required; partition stays read-only until explicit promotion. */
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { fork } from "node:child_process";
import { once } from "node:events";
import { createHmac, createPrivateKey, generateKeyPairSync, randomBytes, randomUUID } from "node:crypto";
import { createIdentity } from "@janjacord/identity";
import { ed25519Fingerprint, ed25519PublicKey, signCanonicalPayload } from "@janjacord/crypto";
import { HostClient } from "@janjacord/networking";
import { createSignedBridgeDescriptor } from "@janjacord/protocol";
import { mintPairingToken } from "./pairing-fixture.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const hostMain = join(__dirname, "..", "..", "janjanode", "dist", "main.js");
const bridgeMain = join(__dirname, "..", "..", "rendezvous", "dist", "main.js");
const primaryPort = 8960;
const replicaPorts = [8961, 8964];
const bridgePorts = [8962, 8963];
const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
let failures = 0;
const assert = (condition, label) => condition
  ? console.log(`  ✓ ${label}`)
  : (failures++, console.error(`  ✗ ${label}`));
const ED25519_PKCS8_SEED_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

async function stopChild(child) {
  if (!child || child.exitCode !== null || child.signalCode !== null) return;
  const exited = once(child, "exit");
  child.kill("SIGTERM");
  await Promise.race([
    exited,
    wait(2_000).then(() => {
      if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
    }),
  ]);
}

function enrollmentKeyPair() {
  const pair = generateKeyPairSync("x25519");
  return {
    publicKey: Buffer.from(pair.publicKey.export({ format: "der", type: "spki" })).subarray(-32),
    privateKey: Buffer.from(pair.privateKey.export({ format: "der", type: "pkcs8" })).subarray(-32),
  };
}

function hostProof(purpose, context, hostSeed) {
  const proofId = randomUUID();
  const issuedAt = Date.now();
  return {
    proofId,
    issuedAt,
    signature: signCanonicalPayload(hostSeed, "janjacord.host-possession.v1", { purpose, ...context, proofId, issuedAt }).toString("base64url"),
  };
}

function candidateProof(domain, context, seed) {
  const proofId = randomUUID();
  const issuedAt = Date.now();
  return { proofId, issuedAt, signature: signCanonicalPayload(seed, domain, { ...context, proofId, issuedAt }).toString("base64url") };
}

function spawn(port, env) {
  const child = fork(hostMain, [], {
    env: { ...process.env, JC_PORT: String(port), ...env },
    stdio: ["ignore", "pipe", "pipe", "ipc"],
    execPath: process.env.JC_NODE_BIN ?? "node",
  });
  child.stdout?.on("data", (data) => process.stdout.write(data));
  child.stderr?.on("data", (data) => process.stderr.write(data));
  return child;
}

async function connect(url, identity, trust) {
  const client = new HostClient(url, {
    identityId: identity.identityId,
    deviceSeed: identity.seed,
    authorityFingerprint: trust.authorityFingerprint,
    ...(trust.serverId ? { serverId: trust.serverId } : {}),
    expectedHostPublicKey: trust.publicKey,
    ...(trust.hostId ? { expectedHostId: trust.hostId } : {}),
    ...(trust.grantId ? { expectedGrantId: trust.grantId } : {}),
  });
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("authenticated connect timeout")), 6_000);
    client.onOpen(() => { clearTimeout(timer); resolve(); });
  });
  return client;
}

async function hello(client, identityId) {
  const result = new Promise((resolve) => client.onEventOnce("result", (frame) => resolve(frame.data)));
  client.send("hello", { identityId });
  return result;
}

async function main() {
  const dir = mkdtempSync(join(tmpdir(), "jc-lease-"));
  let primary;
  const replicas = [];
  const bridges = [];
  try {
    const owner = await createIdentity("owner", "owner-password-123", join(dir, "owner.vault"));
    const member = await createIdentity("member", "member-password-123", join(dir, "member.vault"));
    const contender = await createIdentity("contender", "contender-password-123", join(dir, "contender.vault"));
    const authoritySeed = createHmac("sha256", owner.seed).update("authority").digest();
    const primaryHostSeed = createHmac("sha256", owner.seed).update("primary-host").digest();
    const replicaHostSeed = createHmac("sha256", member.seed).update("replica-host").digest();
    const contenderHostSeed = createHmac("sha256", contender.seed).update("replica-host").digest();
    const enrollmentKeys = enrollmentKeyPair();
    const contenderEnrollmentKeys = enrollmentKeyPair();
    const serverDbKey = randomBytes(32);
    assert(!serverDbKey.equals(owner.dbKey), "server DB key is distinct from identity/MLS DB key");
    assert(!replicaHostSeed.equals(member.seed), "identity and host signing secrets are distinct");
    const authorityFingerprint = ed25519Fingerprint(ed25519PublicKey(authoritySeed));
    const primaryTrust = { authorityFingerprint, publicKey: ed25519PublicKey(primaryHostSeed).toString("base64url") };
    const common = { JC_OWNER_IDENTITY: owner.identityId, JC_OWNER_NICKNAME: owner.nickname, JC_SERVER_NAME: "Lease Smoke" };
    const now = Date.now();
    const bridgeConfigs = bridgePorts.map((port, index) => {
      const bridgeSeed = Buffer.alloc(32, 61 + index);
      const descriptor = createSignedBridgeDescriptor({
        version: 1,
        bridgeId: `ed25519:${ed25519Fingerprint(ed25519PublicKey(bridgeSeed))}`,
        endpoints: [`wss://127.0.0.1:${port}`],
        issuedAt: now,
        expiresAt: now + 120_000,
      }, bridgeSeed);
      const adminKey = `lease-smoke-pairing-admin-key-${index}-0123456789abcdef`;
      const pairingPath = join(dir, `bridge-${index}-pairing-admin-key`);
      const descriptorPath = join(dir, `bridge-${index}-descriptor.json`);
      const signingKeyPath = join(dir, `bridge-${index}-signing-key.pem`);
      writeFileSync(pairingPath, `${adminKey}\n`, { mode: 0o600 });
      writeFileSync(descriptorPath, `${JSON.stringify(descriptor)}\n`, { mode: 0o600 });
      const signingKey = createPrivateKey({
        key: Buffer.concat([ED25519_PKCS8_SEED_PREFIX, bridgeSeed]),
        format: "der",
        type: "pkcs8",
      });
      writeFileSync(signingKeyPath, signingKey.export({ format: "pem", type: "pkcs8" }), { mode: 0o600 });
      return {
        pairingToken: mintPairingToken(descriptor.payload.bridgeId, adminKey),
        pairingPath,
        descriptorPath,
        signingKeyPath,
        statePath: join(dir, `bridge-${index}-state.jsonl`),
        descriptor,
        port,
      };
    });
    const launchBridge = (config) => {
      const bridge = fork(bridgeMain, [], {
        env: {
          ...process.env,
          JC_RENDEZVOUS_PORT: String(config.port),
          JC_BRIDGE_PAIRING_ADMIN_KEY_FILE: config.pairingPath,
          JC_BRIDGE_DESCRIPTOR_FILE: config.descriptorPath,
          JC_BRIDGE_SIGNING_KEY_FILE: config.signingKeyPath,
          JC_RENDEZVOUS_STATE_FILE: config.statePath,
          JC_WITNESS_ABSENCE_GRACE_MS: "3000",
          JC_RENDEZVOUS_RATE_LIMIT: "1000",
        },
        stdio: ["ignore", "pipe", "pipe", "ipc"],
        execPath: process.env.JC_NODE_BIN ?? "node",
      });
      bridge.stdout?.on("data", (data) => process.stdout.write(data));
      bridge.stderr?.on("data", (data) => process.stderr.write(data));
      return bridge;
    };
    for (const config of bridgeConfigs) bridges.push(launchBridge(config));
    await wait(700);

    const primaryEnv = {
      ...common,
      JC_DB_KEY: serverDbKey.toString("hex"),
      JC_DB_PATH: join(dir, "primary.db"),
      JC_OWNER_PUBLIC_KEY: ed25519PublicKey(owner.seed).toString("base64url"),
      JC_AUTHORITY_SIGNING_SEED: authoritySeed.toString("hex"),
      JC_HOST_SIGNING_SEED: primaryHostSeed.toString("hex"),
      JC_BRIDGE_DESCRIPTORS: JSON.stringify(bridgeConfigs.map((entry) => entry.descriptor)),
      JC_BRIDGE_PAIRINGS: JSON.stringify(bridgeConfigs.map((entry) => ({
        bridgeId: entry.descriptor.payload.bridgeId,
        pairingToken: entry.pairingToken,
      }))),
      JC_ALLOW_INSECURE_BRIDGE_LOOPBACK: "1",
      JC_RENDEZVOUS_RENEW_MS: "1200",
    };
    primary = spawn(primaryPort, primaryEnv);
    await wait(1_800);
    const ownerPrimary = await connect(`ws://127.0.0.1:${primaryPort}/signal`, owner, primaryTrust);
    const state = await hello(ownerPrimary, owner.identityId);
    assert(state.ok, "owner authenticates to primary");
    const serverId = state.data.serverId;
    primaryTrust.serverId = serverId;
    const invite = await ownerPrimary.request({ type: "invite.create", initialRoleId: "role-member", maxUses: 2 });
    const memberPrimary = await connect(`ws://127.0.0.1:${primaryPort}/signal`, member, primaryTrust);
    assert((await memberPrimary.request({ type: "server.join", inviteKey: invite.data.inviteKey })).ok, "member joins before host authorization");
    const contenderPrimary = await connect(`ws://127.0.0.1:${primaryPort}/signal`, contender, primaryTrust);
    assert((await contenderPrimary.request({ type: "server.join", inviteKey: invite.data.inviteKey })).ok, "second member joins before concurrent host authorization");

    const prepareReplica = async (identity, client, hostSeed, keys, label) => {
      const candidateHostPublicKey = ed25519PublicKey(hostSeed).toString("base64url");
      const candidateEnrollmentPublicKey = keys.publicKey.toString("base64url");
      const candidateSubjectKey = ed25519PublicKey(identity.seed).toString("base64url");
      const candidateHostId = `lease-${identity.identityId}`;
      const candidateContext = {
        serverId,
        subjectIdentityId: identity.identityId,
        subjectAuthPublicKey: candidateSubjectKey,
        hostPublicKey: candidateHostPublicKey,
        enrollmentPublicKey: candidateEnrollmentPublicKey,
        hostId: candidateHostId,
      };
      const registered = await client.request({
        type: "host.candidate.register",
        hostPublicKey: candidateHostPublicKey,
        enrollmentPublicKey: candidateEnrollmentPublicKey,
        hostId: candidateHostId,
        deviceProof: candidateProof("janjacord.host-candidate-device.v1", candidateContext, identity.seed),
        hostProof: candidateProof("janjacord.host-candidate-possession.v1", candidateContext, hostSeed),
      });
      assert(registered.ok, `${label} registers a proved lease candidate`);
      const created = await ownerPrimary.request({
        type: "host.grant.create",
        subjectIdentityId: identity.identityId,
        candidateId: registered.data.candidate.candidateId,
        capabilities: ["register", "replicate", "promote"],
      });
      const candidateGrantId = created.data.grant.payload.grantId;
      const proofContext = {
        serverId,
        grantId: candidateGrantId,
        subjectIdentityId: identity.identityId,
        subjectAuthPublicKey: candidateSubjectKey,
        hostPublicKey: candidateHostPublicKey,
        enrollmentPublicKey: candidateEnrollmentPublicKey,
      };
      assert((await client.request({ type: "host.grant.accept", grantId: candidateGrantId, hostProof: hostProof("accept", proofContext, hostSeed) })).ok, `${label} accepts promote grant`);
      const enrollment = await client.request({ type: "replica.enroll", grantId: candidateGrantId, hostProof: hostProof("enroll", proofContext, hostSeed) });
      assert(enrollment.ok, `${label} authenticated enrollment succeeds`);
      const enrollmentFile = join(dir, `${label}-enrollment.json`);
      writeFileSync(enrollmentFile, JSON.stringify(enrollment.data), { mode: 0o600 });
      return {
        identity,
        hostSeed,
        keys,
        hostId: candidateHostId,
        hostPublicKey: candidateHostPublicKey,
        grantId: candidateGrantId,
        enrollmentFile,
      };
    };
    const replicaConfigs = [
      await prepareReplica(member, memberPrimary, replicaHostSeed, enrollmentKeys, "replica-a"),
      await prepareReplica(contender, contenderPrimary, contenderHostSeed, contenderEnrollmentKeys, "replica-b"),
    ];
    for (const [index, config] of replicaConfigs.entries()) {
      replicas.push(spawn(replicaPorts[index], {
        ...common,
        JC_DB_PATH: join(dir, `replica-${index}.db`),
        JC_REPLICA_ENROLLMENT_FILE: config.enrollmentFile,
        JC_REPLICA_DEVICE_SEED: config.identity.seed.toString("hex"),
        JC_HOST_SIGNING_SEED: config.hostSeed.toString("hex"),
        JC_REPLICA_ENROLLMENT_PRIVATE_KEY: config.keys.privateKey.toString("hex"),
        JC_LEASE_INTERVAL_MS: "600",
        JC_LEASE_REVOKE_MS: "2200",
        JC_PRIMARY_FENCE_MS: "5000",
        JC_HOST_DIAGNOSTICS: "1",
        JC_ALLOW_INSECURE_BRIDGE_LOOPBACK: "1",
      }));
      await wait(250);
    }
    await wait(14_000); // allows WAN resolve + ICE/DataChannel auth + at least one matching ping
    await stopChild(bridges[0]);
    await wait(500);
    await stopChild(primary);
    await wait(12_000);

    const replicaTrusts = replicaConfigs.map((config) => ({
      authorityFingerprint,
      serverId,
      publicKey: config.hostPublicKey,
      hostId: config.hostId,
      grantId: config.grantId,
    }));
    const partitionClients = await Promise.all(replicaPorts.map((port, index) => (
      connect(`ws://127.0.0.1:${port}/signal`, owner, replicaTrusts[index])
    )));
    const partitionedStates = await Promise.all(partitionClients.map((client) => hello(client, owner.identityId)));
    assert(partitionedStates.every((entry) => entry.ok && !entry.data.hosting.writer), "one of two bridges down leaves both concurrent replicas read-only");
    assert((await Promise.all(partitionClients.map((client, index) => client.request({
      type: "channel.create", channelType: "text", name: `must-not-write-${index}`,
    })))).every((result) => !result.ok), "one-of-two partition cannot accept writes on either replica");
    partitionClients.forEach((client) => client.close());

    bridges[0] = launchBridge(bridgeConfigs[0]);
    await wait(1_000);
    // A bridge that was offline at the moment of failure must not invent an absence
    // observation after restart. Rebind the same primary to both independent bridges,
    // then kill it while both are live so each witness observes the authenticated close.
    primary = spawn(primaryPort, primaryEnv);
    await wait(8_000);
    await stopChild(primary);
    await wait(12_000);
    const electionClients = await Promise.all(replicaPorts.map((port, index) => (
      connect(`ws://127.0.0.1:${port}/signal`, owner, replicaTrusts[index])
    )));
    const electionStates = await Promise.all(electionClients.map((client) => hello(client, owner.identityId)));
    const writerIndexes = electionStates
      .map((entry, index) => entry.ok && entry.data.hosting.writer ? index : -1)
      .filter((index) => index >= 0);
    assert(electionStates.every((entry) => entry.ok && entry.data.serverId === serverId), "both replicas retain the same server after primary loss");
    assert(writerIndexes.length === 1, "durable bridge election permits exactly one writer among two concurrent replicas");
    const writerIndex = writerIndexes[0] ?? 0;
    const loserIndex = writerIndex === 0 ? 1 : 0;
    const ownerReplica = electionClients[writerIndex];
    const promotedState = electionStates[writerIndex];
    assert(promotedState.data.hosting.writer && promotedState.data.epoch === state.data.epoch + 1, "winner holds the next epoch after 2/2 promotion votes");
    assert(!electionStates[loserIndex].data.hosting.writer, "losing concurrent replica remains fenced read-only at the old epoch");
    await wait(6_500);
    const sustainedState = await ownerReplica.request({ type: "server.state" });
    assert(sustainedState.ok && sustainedState.data.hosting.writer, "promoted replica registers immediately and remains writer beyond the fence window");
    const write = await ownerReplica.request({ type: "channel.create", channelType: "text", name: "after-witness-promote" });
    assert(write.ok, "witness-promoted host accepts writes");
    assert(!(await electionClients[loserIndex].request({ type: "channel.create", channelType: "text", name: "concurrent-loser-must-not-write" })).ok, "concurrent election loser rejects writes");
    assert(promotedState.data.redundancy.twoSafe === false, "redundancy remains honestly snapshot-only");

    primary = spawn(primaryPort, primaryEnv);
    await wait(4_000);
    const oldPrimary = await connect(`ws://127.0.0.1:${primaryPort}/signal`, owner, primaryTrust);
    const oldPrimaryState = await hello(oldPrimary, owner.identityId);
    assert(oldPrimaryState.ok && !oldPrimaryState.data.hosting.writer, "returning old Primary observes the higher epoch and self-fences");
    assert(!(await oldPrimary.request({ type: "channel.create", channelType: "text", name: "split-brain-write" })).ok, "returning old Primary rejects stale writes");
    oldPrimary.close();

    ownerPrimary.close();
    memberPrimary.close();
    contenderPrimary.close();
    electionClients.forEach((client) => client.close());
  } finally {
    await stopChild(primary);
    for (const replica of replicas) await stopChild(replica);
    for (const bridge of bridges) await stopChild(bridge);
    rmSync(dir, { recursive: true, force: true });
  }
  if (failures) throw new Error(`${failures} lease smoke assertion(s) failed`);
  console.log("[smoke-lease] WAN DATACHANNEL SYNC + 2/2 DURABLE VOTE + TWO-REPLICA SINGLE-WRITER ELECTION OK");
}

main().catch((error) => { console.error("[smoke-lease]", error); process.exitCode = 1; });
