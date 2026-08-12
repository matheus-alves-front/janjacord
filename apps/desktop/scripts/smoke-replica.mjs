/** Real authenticated enrollment/snapshot sync; zero-bridge failover stays read-only. */
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { fork } from "node:child_process";
import { createHmac, generateKeyPairSync, randomBytes, randomUUID } from "node:crypto";
import { createIdentity } from "@janjacord/identity";
import { ed25519Fingerprint, ed25519PublicKey, signCanonicalPayload } from "@janjacord/crypto";
import { HostClient } from "@janjacord/networking";

const __dirname = dirname(fileURLToPath(import.meta.url));
const hostMain = join(__dirname, "..", "..", "janjanode", "dist", "main.js");
const primaryPort = 8940;
const replicaPort = 8941;
let failures = 0;

const assert = (condition, label) => {
  if (condition) console.log(`  ✓ ${label}`);
  else { failures++; console.error(`  ✗ ${label}`); }
};
const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

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
  const payload = { purpose, ...context, proofId, issuedAt };
  return {
    proofId,
    issuedAt,
    signature: signCanonicalPayload(hostSeed, "janjacord.host-possession.v1", payload).toString("base64url"),
  };
}

function candidateProof(domain, context, seed) {
  const proofId = randomUUID();
  const issuedAt = Date.now();
  return { proofId, issuedAt, signature: signCanonicalPayload(seed, domain, { ...context, proofId, issuedAt }).toString("base64url") };
}

function spawnHost(port, env) {
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
  const dir = mkdtempSync(join(tmpdir(), "jc-replica-"));
  let primary;
  let replica;
  try {
    const owner = await createIdentity("owner", "owner-password-123", join(dir, "owner.vault"));
    const member = await createIdentity("member", "member-password-123", join(dir, "member.vault"));
    const authoritySeed = createHmac("sha256", owner.seed).update("authority").digest();
    const primaryHostSeed = createHmac("sha256", owner.seed).update("primary-host").digest();
    const replicaHostSeed = createHmac("sha256", member.seed).update("replica-host").digest();
    const enrollmentKeys = enrollmentKeyPair();
    const serverDbKey = randomBytes(32);
    assert(!serverDbKey.equals(owner.dbKey), "server DB key is distinct from identity/MLS DB key");
    const subjectAuthPublicKey = ed25519PublicKey(member.seed).toString("base64url");
    const hostPublicKey = ed25519PublicKey(replicaHostSeed).toString("base64url");
    const enrollmentPublicKey = enrollmentKeys.publicKey.toString("base64url");
    assert(!replicaHostSeed.equals(member.seed), "identity seed and host signing seed are distinct");
    const authorityFingerprint = ed25519Fingerprint(ed25519PublicKey(authoritySeed));
    const primaryTrust = {
      authorityFingerprint,
      publicKey: ed25519PublicKey(primaryHostSeed).toString("base64url"),
    };
    const common = {
      JC_OWNER_IDENTITY: owner.identityId,
      JC_OWNER_NICKNAME: owner.nickname,
      JC_SERVER_NAME: "Replica Smoke",
    };

    primary = spawnHost(primaryPort, {
      ...common,
      JC_DB_KEY: serverDbKey.toString("hex"),
      JC_DB_PATH: join(dir, "primary.db"),
      JC_OWNER_PUBLIC_KEY: ed25519PublicKey(owner.seed).toString("base64url"),
      JC_AUTHORITY_SIGNING_SEED: authoritySeed.toString("hex"),
      JC_HOST_SIGNING_SEED: primaryHostSeed.toString("hex"),
    });
    await wait(1_800);

    const ownerPrimary = await connect(`ws://127.0.0.1:${primaryPort}/signal`, owner, primaryTrust);
    const ownerState = await hello(ownerPrimary, owner.identityId);
    assert(ownerState?.ok, "owner authenticates to primary with signed challenge");
    const serverId = ownerState.data.serverId;
    primaryTrust.serverId = serverId;

    const invite = await ownerPrimary.request({ type: "invite.create", initialRoleId: "role-member", maxUses: 1 });
    assert(invite.ok && invite.data.inviteKey.startsWith("JC2-"), "no-bridge invite honestly falls back to self-contained JC2");
    const memberPrimary = await connect(`ws://127.0.0.1:${primaryPort}/signal`, member, primaryTrust);
    const joined = await memberPrimary.request({ type: "server.join", inviteKey: invite.data.inviteKey });
    assert(joined.ok, "member joins with a real signed device identity");

    const hostId = `replica-${member.identityId}`;
    const candidateContext = { serverId, subjectIdentityId: member.identityId, subjectAuthPublicKey, hostPublicKey, enrollmentPublicKey, hostId };
    const registered = await memberPrimary.request({
      type: "host.candidate.register",
      hostPublicKey,
      enrollmentPublicKey,
      hostId,
      deviceProof: candidateProof("janjacord.host-candidate-device.v1", candidateContext, member.seed),
      hostProof: candidateProof("janjacord.host-candidate-possession.v1", candidateContext, replicaHostSeed),
    });
    assert(registered.ok, "member registers a proved host candidate before owner authorization");
    const candidateId = registered.data.candidate.candidateId;
    const created = await ownerPrimary.request({
      type: "host.grant.create",
      subjectIdentityId: member.identityId,
      candidateId,
      capabilities: ["register", "replicate", "promote"],
    });
    assert(created.ok && created.data.candidateId === candidateId, "owner creates grant by candidateId without handling keys");
    const grantId = created.data.grant.payload.grantId;
    const proofContext = { serverId, grantId, subjectIdentityId: member.identityId, subjectAuthPublicKey, hostPublicKey, enrollmentPublicKey };
    const accepted = await memberPrimary.request({ type: "host.grant.accept", grantId, hostProof: hostProof("accept", proofContext, replicaHostSeed) });
    assert(accepted.ok, "member explicitly accepts hosting grant");
    const enrolled = await memberPrimary.request({ type: "replica.enroll", grantId, hostProof: hostProof("enroll", proofContext, replicaHostSeed) });
    assert(enrolled.ok && enrolled.data.sealedEnrollment?.ciphertext, "accepted replicate grant receives a sealed enrollment envelope");
    assert(!JSON.stringify(enrolled.data).includes("dbKeyB64") && !JSON.stringify(enrolled.data).includes("dbB64"), "DB key and snapshot never cross the application transport in plaintext");

    const enrollmentFile = join(dir, "replica-enrollment.json");
    writeFileSync(enrollmentFile, JSON.stringify(enrolled.data), { mode: 0o600 });
    replica = spawnHost(replicaPort, {
      ...common,
      JC_DB_PATH: join(dir, "replica.db"),
      JC_REPLICA_OF: `ws://127.0.0.1:${primaryPort}/signal`,
      JC_REPLICA_ENROLLMENT_FILE: enrollmentFile,
      JC_REPLICA_DEVICE_SEED: member.seed.toString("hex"),
      JC_HOST_SIGNING_SEED: replicaHostSeed.toString("hex"),
      JC_REPLICA_ENROLLMENT_PRIVATE_KEY: enrollmentKeys.privateKey.toString("hex"),
      JC_LEASE_INTERVAL_MS: "700",
      JC_LEASE_REVOKE_MS: "2500",
    });
    await wait(2_000);

    const replicaTrust = {
      authorityFingerprint,
      serverId,
      publicKey: hostPublicKey,
      hostId,
      grantId,
    };
    const ownerReplicaBefore = await connect(`ws://127.0.0.1:${replicaPort}/signal`, owner, replicaTrust);
    const preWrite = await ownerReplicaBefore.request({ type: "channel.create", channelType: "text", name: "must-fail" });
    assert(!preWrite.ok && preWrite.error.code === "conflict", "configured replica rejects ordinary writes before promotion");
    ownerReplicaBefore.close();

    const channel = await ownerPrimary.request({ type: "channel.create", channelType: "text", name: "synced-after-start" });
    assert(channel.ok, "primary accepts state change after replica startup");
    await wait(2_500);
    const ownerReplica = await connect(`ws://127.0.0.1:${replicaPort}/signal`, owner, replicaTrust);
    const replicaState = await hello(ownerReplica, owner.identityId);
    assert(replicaState.ok && replicaState.data.serverId === serverId, "replica preserves serverId and authority");
    assert(replicaState.data.channels.some((item) => item.name === "synced-after-start"), "periodic authenticated sync replaces DB through Store boundary");
    assert(replicaState.data.redundancy.twoSafe === false, "status does not claim op-log/2-safe ACK");
    ownerReplica.close();

    primary.kill();
    await wait(4_000);
    const memberReplica = await connect(`ws://127.0.0.1:${replicaPort}/signal`, member, replicaTrust);
    const beforePromotion = await hello(memberReplica, member.identityId);
    const promoted = await memberReplica.request({ type: "replica.promote", grantId, expectedEpoch: beforePromotion.data.epoch });
    assert(!promoted.ok && promoted.error.code === "invalid_input", "manual replica.promote is absent from the public command API");
    const afterPromotion = await memberReplica.request({ type: "server.state" });
    assert(afterPromotion.ok && afterPromotion.data.epoch === beforePromotion.data.epoch && !afterPromotion.data.hosting.writer, "zero-bridge replica remains same-epoch read-only after primary loss");
    const ownerReplicaAfter = await connect(`ws://127.0.0.1:${replicaPort}/signal`, owner, replicaTrust);
    const postWrite = await ownerReplicaAfter.request({ type: "channel.create", channelType: "text", name: "post-failover" });
    assert(!postWrite.ok && postWrite.error.code === "conflict", "zero-bridge partition cannot accept writes");

    ownerPrimary.close();
    memberPrimary.close();
    memberReplica.close();
    ownerReplicaAfter.close();
  } finally {
    primary?.kill();
    replica?.kill();
    rmSync(dir, { recursive: true, force: true });
  }
  if (failures) throw new Error(`${failures} replica smoke assertion(s) failed`);
  console.log("[smoke-replica] AUTHENTICATED ENROLLMENT + ZERO-BRIDGE FAIL-CLOSED OK");
}

main().catch((error) => { console.error("[smoke-replica]", error); process.exitCode = 1; });
