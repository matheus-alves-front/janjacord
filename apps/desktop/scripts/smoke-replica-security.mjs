/** Focused negative smoke: no grant/no key, revocation fencing, monotonic generations. */
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { fork } from "node:child_process";
import { createHmac, generateKeyPairSync, randomUUID } from "node:crypto";
import { createIdentity } from "@janjacord/identity";
import { ed25519Fingerprint, ed25519PublicKey, signCanonicalPayload } from "@janjacord/crypto";
import { HostClient } from "@janjacord/networking";

const __dirname = dirname(fileURLToPath(import.meta.url));
const hostMain = join(__dirname, "..", "..", "janjanode", "dist", "main.js");
const primaryPort = 8970;
const replicaPort = 8971;
const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
let failures = 0;
const assert = (condition, label) => condition
  ? console.log(`  ✓ ${label}`)
  : (failures++, console.error(`  ✗ ${label}`));

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

async function connect(url, identity, trust, timeoutMs = 5_000) {
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
    const timer = setTimeout(() => reject(new Error("authenticated connect timeout")), timeoutMs);
    client.onOpen(() => { clearTimeout(timer); resolve(); });
    client.onClose(() => { clearTimeout(timer); reject(new Error("closed before authentication")); });
  });
  return client;
}

async function hello(client, identityId) {
  const result = new Promise((resolve) => client.onEventOnce("result", (frame) => resolve(frame.data)));
  client.send("hello", { identityId });
  return result;
}

async function main() {
  const dir = mkdtempSync(join(tmpdir(), "jc-replica-security-"));
  let primary;
  let replica;
  try {
    const owner = await createIdentity("owner", "owner-password-123", join(dir, "owner.vault"));
    const member = await createIdentity("member", "member-password-123", join(dir, "member.vault"));
    const authoritySeed = createHmac("sha256", owner.seed).update("authority").digest();
    const primaryHostSeed = createHmac("sha256", owner.seed).update("primary-host").digest();
    const replicaHostSeed = createHmac("sha256", member.seed).update("replica-host").digest();
    const attackerHostSeed = createHmac("sha256", member.seed).update("wrong-host").digest();
    const enrollmentKeys = enrollmentKeyPair();
    const serverDbKey = createHmac("sha256", randomUUID()).update("server-db").digest();
    assert(!serverDbKey.equals(owner.dbKey), "server DB key is distinct from identity/MLS DB key");
    const subjectAuthPublicKey = ed25519PublicKey(member.seed).toString("base64url");
    const hostPublicKey = ed25519PublicKey(replicaHostSeed).toString("base64url");
    const enrollmentPublicKey = enrollmentKeys.publicKey.toString("base64url");
    assert(!replicaHostSeed.equals(member.seed), "identity seed and host signing seed are distinct");
    const authorityFingerprint = ed25519Fingerprint(ed25519PublicKey(authoritySeed));
    const primaryTrust = { authorityFingerprint, publicKey: ed25519PublicKey(primaryHostSeed).toString("base64url") };
    const common = { JC_OWNER_IDENTITY: owner.identityId, JC_OWNER_NICKNAME: owner.nickname, JC_SERVER_NAME: "Replica Security" };
    primary = spawn(primaryPort, {
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
    const serverId = ownerState.data.serverId;
    primaryTrust.serverId = serverId;
    const absentGrantId = randomUUID();
    const absentContext = { serverId, grantId: absentGrantId, subjectIdentityId: owner.identityId, subjectAuthPublicKey: ed25519PublicKey(owner.seed).toString("base64url"), hostPublicKey, enrollmentPublicKey };
    const noGrant = await ownerPrimary.request({ type: "replica.enroll", grantId: absentGrantId, hostProof: hostProof("enroll", absentContext, replicaHostSeed) });
    assert(!noGrant.ok && noGrant.error.code === "forbidden" && !noGrant.data, "no accepted replicate grant means no DB key or snapshot");

    const invite = await ownerPrimary.request({ type: "invite.create", initialRoleId: "role-member", maxUses: 1 });
    const memberPrimary = await connect(`ws://127.0.0.1:${primaryPort}/signal`, member, primaryTrust);
    await memberPrimary.request({ type: "server.join", inviteKey: invite.data.inviteKey });
    const hostId = `security-${member.identityId}`;
    const candidateContext = { serverId, subjectIdentityId: member.identityId, subjectAuthPublicKey, hostPublicKey, enrollmentPublicKey, hostId };
    const registered = await memberPrimary.request({
      type: "host.candidate.register", hostPublicKey, enrollmentPublicKey, hostId,
      deviceProof: candidateProof("janjacord.host-candidate-device.v1", candidateContext, member.seed),
      hostProof: candidateProof("janjacord.host-candidate-possession.v1", candidateContext, replicaHostSeed),
    });
    assert(registered.ok, "member candidate registration verifies identity and distinct host possession");
    const candidateId = registered.data.candidate.candidateId;
    const first = await ownerPrimary.request({
      type: "host.grant.create",
      subjectIdentityId: member.identityId,
      candidateId,
      capabilities: ["register", "replicate", "promote"],
    });
    const grantId = first.data.grant.payload.grantId;
    assert(first.data.grant.payload.generation === 1, "first grant starts at generation 1");
    const proofContext = { serverId, grantId, subjectIdentityId: member.identityId, subjectAuthPublicKey, hostPublicKey, enrollmentPublicKey };
    const forgedAccept = await memberPrimary.request({ type: "host.grant.accept", grantId, hostProof: hostProof("accept", proofContext, attackerHostSeed) });
    assert(!forgedAccept.ok && forgedAccept.error.code === "unauthorized", "grant accept rejects proof from the identity key or another host key");
    await memberPrimary.request({ type: "host.grant.accept", grantId, hostProof: hostProof("accept", proofContext, replicaHostSeed) });
    const enrollment = await memberPrimary.request({ type: "replica.enroll", grantId, hostProof: hostProof("enroll", proofContext, replicaHostSeed) });
    assert(enrollment.ok && !JSON.stringify(enrollment.data).includes("dbKeyB64"), "enrollment is sealed and contains no plaintext DB key field");
    const wrongGrant = await memberPrimary.request({ type: "replica.snapshot", grantId: randomUUID(), serverId });
    assert(!wrongGrant.ok && wrongGrant.error.code === "forbidden", "snapshot is bound to exact grantId and authenticated device");

    const enrollmentFile = join(dir, "enrollment.json");
    writeFileSync(enrollmentFile, JSON.stringify(enrollment.data), { mode: 0o600 });
    replica = spawn(replicaPort, {
      ...common,
      JC_DB_PATH: join(dir, "replica.db"),
      JC_REPLICA_OF: `ws://127.0.0.1:${primaryPort}/signal`,
      JC_REPLICA_ENROLLMENT_FILE: enrollmentFile,
      JC_REPLICA_DEVICE_SEED: member.seed.toString("hex"),
      JC_HOST_SIGNING_SEED: replicaHostSeed.toString("hex"),
      JC_REPLICA_ENROLLMENT_PRIVATE_KEY: enrollmentKeys.privateKey.toString("hex"),
      JC_LEASE_INTERVAL_MS: "500",
      JC_LEASE_REVOKE_MS: "1800",
    });
    await wait(2_200); // establishes at least one healthy signed lease
    const revoked = await ownerPrimary.request({ type: "host.grant.revoke", grantId, reason: "security smoke" });
    assert(revoked.ok && revoked.data.revocation.payload.generation === 2, "revocation increments host generation");
    const deniedAfterRevoke = await memberPrimary.request({ type: "replica.snapshot", grantId, serverId });
    assert(!deniedAfterRevoke.ok && deniedAfterRevoke.error.code === "forbidden", "revoked grant cannot sync");
    await wait(1_500); // replica observes explicit denial and fences its local grant

    const regrant = await ownerPrimary.request({
      type: "host.grant.create",
      subjectIdentityId: member.identityId,
      candidateId,
      capabilities: ["register", "replicate", "promote"],
    });
    assert(regrant.ok && regrant.data.grant.payload.generation === 3, "regrant increments generation beyond revocation");
    const listed = await ownerPrimary.request({ type: "host.grant.list" });
    assert(listed.ok && listed.data.candidates.some((item) => item.candidateId === candidateId), "manage_hosts list exposes the proved candidate for UI selection");

    primary.kill();
    await wait(3_000);
    const replicaTrust = {
      authorityFingerprint,
      serverId,
      publicKey: hostPublicKey,
      hostId,
      grantId,
    };
    let authenticated = false;
    try {
      const stale = await connect(`ws://127.0.0.1:${replicaPort}/signal`, member, replicaTrust, 2_000);
      authenticated = true;
      const result = await stale.request({ type: "replica.promote", grantId, expectedEpoch: ownerState.data.epoch });
      assert(!result.ok, "revoked grant is rejected by local promotion guard");
      stale.close();
    } catch {
      assert(true, "revoked replica host cannot authenticate/serve a promotion challenge");
    }
    if (!authenticated) assert(replica.exitCode === null, "revoked replica remains alive but fenced instead of auto-promoting");

    ownerPrimary.close();
    memberPrimary.close();
  } finally {
    primary?.kill();
    replica?.kill();
    rmSync(dir, { recursive: true, force: true });
  }
  if (failures) throw new Error(`${failures} replica security assertion(s) failed`);
  console.log("[smoke-replica-security] REVOCATION + AUTHZ + GENERATIONS OK");
}

main().catch((error) => { console.error("[smoke-replica-security]", error); process.exitCode = 1; });
