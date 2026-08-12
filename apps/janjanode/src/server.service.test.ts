import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { generateKeyPairSync, randomUUID } from "node:crypto";
import { ed25519Fingerprint, ed25519PublicKey, parseInviteKey, sha256Hex, signCanonicalPayload } from "@janjacord/crypto";
import {
  attachmentSha256,
  buildEnvelope,
  createSignedBridgeDescriptor,
  createSignedHostGrant,
  createSignedHostRecord,
  encodeAttachmentChunks,
  hostRegistrationRecordHash,
  parseInviteV3,
} from "@janjacord/protocol";
import { createSignedIceAccessProof } from "@janjacord/networking";
import { Store } from "./store.js";
import {
  MAX_PENDING_ATTACHMENT_TRANSFERS_PER_MEMBER,
  ServerService,
  strictBridgeWitnessQuorum,
  validObservedPromotionCertificate,
  verifyReplicaEnrollmentTranscript,
} from "./server.service.js";

const dirs: string[] = [];

function uploadAttachment(
  service: ServerService,
  input: { actorId?: string; assetId: string; channelId: string; audience?: string[]; ciphertext: Buffer },
) {
  const actorId = input.actorId ?? "owner";
  const audience = input.audience ?? [actorId];
  const chunks = encodeAttachmentChunks(input.ciphertext);
  const begun = service.attachmentUploadBegin(
    actorId,
    input.assetId,
    input.channelId,
    audience,
    input.ciphertext.length,
    chunks.length,
    attachmentSha256(input.ciphertext),
  );
  if (!begun.ok) return { result: begun, chunks };
  for (const chunk of chunks) {
    const uploaded = service.attachmentUploadChunk(actorId, input.assetId, chunk.index, chunk.data, chunk.sizeBytes, chunk.hash);
    if (!uploaded.ok) return { result: uploaded, chunks };
  }
  return { result: service.attachmentUploadComplete(actorId, input.assetId), chunks };
}

function serviceFixture(replica = false) {
  const dir = mkdtempSync(join(tmpdir(), "jc-server-service-"));
  dirs.push(dir);
  const authoritySeed = Buffer.alloc(32, 11);
  const hostSeed = Buffer.alloc(32, 12);
  const ownerSeed = Buffer.alloc(32, 13);
  process.env.JC_AUTHORITY_SIGNING_SEED = authoritySeed.toString("hex");
  process.env.JC_HOST_SIGNING_SEED = hostSeed.toString("hex");
  process.env.JC_OWNER_PUBLIC_KEY = ed25519PublicKey(ownerSeed).toString("base64url");
  process.env.JC_PORT = "8999";
  if (replica) process.env.JC_REPLICA_OF = "auto";
  else delete process.env.JC_REPLICA_OF;
  delete process.env.JC_BRIDGE_DESCRIPTORS;
  delete process.env.JC_DIRECT_ENDPOINT;
  const file = join(dir, "server.db");
  const key = Buffer.alloc(32, 21);
  const store = new Store(file, key);
  store.raw.prepare("INSERT INTO server_meta (key, value) VALUES ('server_id', ?)")
    .run("11111111-1111-4111-8111-111111111111");
  const service = new ServerService(
    store,
    "11111111-1111-4111-8111-111111111111",
    join(dir, "server.db"),
    "owner",
    "Owner",
    "Test",
  );
  service.bootstrap();
  return { service, store, file, key };
}

function reopenService(file: string, key: Buffer): { service: ServerService; store: Store } {
  const store = new Store(file, key);
  const service = new ServerService(
    store,
    "11111111-1111-4111-8111-111111111111",
    file,
    "owner",
    "Owner",
    "Test",
  );
  service.bootstrap();
  return { service, store };
}

function configuredBridgeDescriptors(count = 2) {
  const now = Date.now();
  return Array.from({ length: count }, (_, index) => Buffer.alloc(32, 71 + index)).map((seed, index) => createSignedBridgeDescriptor({
    version: 1,
    bridgeId: `ed25519:${ed25519Fingerprint(ed25519PublicKey(seed))}`,
    endpoints: [`wss://restart-bridge-${index}.example/rendezvous`],
    issuedAt: now - 1_000,
    expiresAt: now + 60_000,
  }, seed));
}

function seedLegacyWriterWithReplicaEnrollment(
  service: ServerService,
  store: Store,
  suffix: string,
  options: {
    capabilities?: ("register" | "replicate" | "promote")[];
    witnessBridgeIds?: string[];
  } = {},
) {
  const current = service.createPrimaryRegistration(`wss://primary-${suffix}.example/signaling`);
  if (!current.ok) throw new Error(current.error.message);
  const now = Date.now();
  const replicaSeed = Buffer.alloc(32, 90);
  const replicaGrant = createSignedHostGrant({
    version: 1,
    grantId: randomUUID(),
    serverId: current.data.registration.record.payload.serverId,
    issuerIdentityId: "owner",
    subjectIdentityId: "owner",
    subjectAuthPublicKey: process.env.JC_OWNER_PUBLIC_KEY!,
    devicePublicKey: ed25519PublicKey(replicaSeed).toString("base64url"),
    hostId: `legacy-enrolled-replica-${suffix}`,
    capabilities: options.capabilities ?? ["register", "replicate", "promote"],
    ...(options.witnessBridgeIds ? { witnessBridgeIds: options.witnessBridgeIds } : {}),
    generation: 1,
    issuedAt: now - 1_000,
    expiresAt: now + 60_000,
  }, Buffer.alloc(32, 11));
  store.raw.prepare(
    "INSERT INTO host_grants (grant_id, subject_identity_id, host_id, subject_auth_public_key, device_public_key, capabilities, payload, signature, expires_at, created_at, accepted_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
  ).run(
    replicaGrant.payload.grantId,
    replicaGrant.payload.subjectIdentityId,
    replicaGrant.payload.hostId,
    replicaGrant.payload.subjectAuthPublicKey,
    replicaGrant.payload.devicePublicKey,
    JSON.stringify(replicaGrant.payload.capabilities),
    JSON.stringify(replicaGrant.payload),
    replicaGrant.signature,
    replicaGrant.payload.expiresAt,
    now - 1_000,
    now - 500,
  );
  store.raw.prepare(
    `INSERT INTO replica_enrollments
     (enrollment_id, grant_id, generation, snapshot_hash, epoch, seq, issued_at, expires_at, consumed_at)
     VALUES (?,?,?,?,?,?,?,?,?)`,
  ).run(randomUUID(), replicaGrant.payload.grantId, 1, "cd".repeat(32), 0, 0, now - 500, now + 60_000, now - 500);
  store.raw.prepare("UPDATE server_meta SET value = ? WHERE key = ?").run(JSON.stringify({
    version: 1,
    state: "writer",
    hostId: current.data.registration.record.payload.hostId,
    grantId: current.data.registration.record.payload.grantId,
    epoch: 0,
    updatedAt: now,
  }), `writer_state:${current.data.registration.record.payload.hostId}`);
  service.abandonPrimaryRegistration(current.data.recordHash);
  return {
    replicaGrantId: replicaGrant.payload.grantId,
    writerStateKey: `writer_state:${current.data.registration.record.payload.hostId}`,
  };
}

afterEach(() => {
  delete process.env.JC_AUTHORITY_SIGNING_SEED;
  delete process.env.JC_HOST_SIGNING_SEED;
  delete process.env.JC_OWNER_PUBLIC_KEY;
  delete process.env.JC_PORT;
  delete process.env.JC_REPLICA_OF;
  delete process.env.JC_BRIDGE_DESCRIPTORS;
  delete process.env.JC_RENDEZVOUS_URL;
  delete process.env.JC_PUBLIC_URL;
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

describe("ServerService host records", () => {
  it("emits the exact consumed invite id after a successful join", () => {
    const { service, store } = serviceFixture();
    try {
      const invite = service.inviteCreate("owner", "role-member", 1);
      if (!invite.ok) throw new Error(invite.error.message);
      const consumed: string[] = [];
      service.events.on("inviteUsed", (inviteId: string) => consumed.push(inviteId));

      expect(service.joinByInvite(
        "member-invite-event",
        "Member",
        invite.data.inviteKey,
        ed25519PublicKey(Buffer.alloc(32, 78)).toString("base64url"),
      ).ok).toBe(true);
      expect(consumed).toEqual([invite.data.inviteId]);
    } finally {
      store.close();
    }
  });

  it("notifies connected owners when a member KeyPackage becomes available", () => {
    const { service, store } = serviceFixture();
    try {
      const invite = service.inviteCreate("owner", "role-member", 1);
      if (!invite.ok) throw new Error(invite.error.message);
      const joined = service.joinByInvite(
        "member-with-key-package",
        "Member",
        invite.data.inviteKey,
        ed25519PublicKey(Buffer.alloc(32, 79)).toString("base64url"),
      );
      if (!joined.ok) throw new Error(joined.error.message);
      let stateChanges = 0;
      service.events.on("stateChanged", () => { stateChanges += 1; });

      expect(service.keyPackageUpload("member-with-key-package", "key-package-data")).toEqual({ ok: true, data: null });
      expect(stateChanges).toBe(1);
    } finally {
      store.close();
    }
  });

  it("restricts MLS commits to the owner and keeps Welcome delivery idempotent until recipient ack", () => {
    const { service, store } = serviceFixture();
    try {
      const invite = service.inviteCreate("owner", "role-member", 2);
      if (!invite.ok) throw new Error(invite.error.message);
      expect(service.joinByInvite(
        "recipient",
        "Recipient",
        invite.data.inviteKey,
        ed25519PublicKey(Buffer.alloc(32, 80)).toString("base64url"),
      ).ok).toBe(true);
      expect(service.joinByInvite(
        "other-member",
        "Other",
        invite.data.inviteKey,
        ed25519PublicKey(Buffer.alloc(32, 81)).toString("base64url"),
      ).ok).toBe(true);
      expect(service.keyPackageUpload("recipient", "recipient-key-package")).toEqual({ ok: true, data: null });

      expect(service.keyPackageGet("recipient", "recipient"))
        .toMatchObject({ ok: false, error: { code: "forbidden" } });
      expect(service.keyPackageGet("owner", "recipient"))
        .toEqual({ ok: true, data: { keyPackageB64: "recipient-key-package" } });
      expect(service.welcomePush("recipient", "recipient", "welcome-v1"))
        .toMatchObject({ ok: false, error: { code: "forbidden" } });

      let deliveries = 0;
      service.events.on("welcome", () => { deliveries += 1; });
      expect(service.welcomePush("owner", "recipient", "welcome-v1")).toEqual({ ok: true, data: null });
      expect(service.welcomePush("owner", "recipient", "welcome-v1")).toEqual({ ok: true, data: null });
      expect(deliveries).toBe(1);
      expect(service.welcomePush("owner", "recipient", "welcome-v2"))
        .toMatchObject({ ok: false, error: { code: "conflict" } });

      const pending = service.welcomePending("recipient");
      expect(pending).toEqual({
        ok: true,
        data: { welcomeId: sha256Hex("welcome-v1"), welcomeB64: "welcome-v1" },
      });
      expect(service.welcomePending("recipient")).toEqual(pending);
      expect(service.welcomeAckConsumed("other-member", sha256Hex("welcome-v1")))
        .toEqual({ ok: true, data: null });
      expect(service.welcomePending("recipient")).toEqual(pending);
      expect(service.welcomeAckConsumed("recipient", sha256Hex("stale-welcome")))
        .toEqual({ ok: true, data: null });
      expect(service.welcomePending("recipient")).toEqual(pending);
      expect(service.welcomeAckConsumed("recipient", sha256Hex("welcome-v1")))
        .toEqual({ ok: true, data: null });
      expect(service.welcomePending("recipient")).toEqual({ ok: true, data: null });
      expect(service.welcomeAckConsumed("recipient", sha256Hex("welcome-v1")))
        .toEqual({ ok: true, data: null });

      expect(service.transferOwnership("owner", "other-member")).toEqual({ ok: true, data: null });
      expect(service.keyPackageGet("owner", "recipient"))
        .toMatchObject({ ok: false, error: { code: "forbidden" } });
      expect(service.keyPackageGet("other-member", "recipient"))
        .toEqual({ ok: true, data: { keyPackageB64: "recipient-key-package" } });
      expect(service.welcomePush("other-member", "recipient", "welcome-v2"))
        .toEqual({ ok: true, data: null });
      expect(service.welcomeAckConsumed("recipient", sha256Hex("welcome-v1")))
        .toEqual({ ok: true, data: null });
      expect(service.welcomePending("recipient")).toEqual({
        ok: true,
        data: { welcomeId: sha256Hex("welcome-v2"), welcomeB64: "welcome-v2" },
      });
    } finally {
      store.close();
    }
  });

  it("persists an unacknowledged Welcome across service restart", () => {
    const fixture = serviceFixture();
    let activeStore = fixture.store;
    try {
      const invite = fixture.service.inviteCreate("owner", "role-member", 1);
      if (!invite.ok) throw new Error(invite.error.message);
      expect(fixture.service.joinByInvite(
        "recipient",
        "Recipient",
        invite.data.inviteKey,
        ed25519PublicKey(Buffer.alloc(32, 82)).toString("base64url"),
      ).ok).toBe(true);
      expect(fixture.service.welcomePush("owner", "recipient", "durable-welcome"))
        .toEqual({ ok: true, data: null });

      activeStore.close();
      const reopened = reopenService(fixture.file, fixture.key);
      activeStore = reopened.store;
      expect(reopened.service.welcomePending("recipient"))
        .toEqual({
          ok: true,
          data: { welcomeId: sha256Hex("durable-welcome"), welcomeB64: "durable-welcome" },
        });
      expect(reopened.service.welcomeAckConsumed("recipient", sha256Hex("durable-welcome")))
        .toEqual({ ok: true, data: null });
      expect(reopened.service.welcomePending("recipient")).toEqual({ ok: true, data: null });
    } finally {
      activeStore.close();
    }
  });

  it("authorizes ICE/TURN only for a signed member device or a live JC3 invite capability hash", () => {
    const { service, store } = serviceFixture();
    try {
      const invite = service.inviteCreate("owner", "role-member", 1);
      if (!invite.ok) throw new Error(invite.error.message);
      const parsedV3 = parseInviteV3(invite.data.inviteKey);
      const parsedLegacy = parsedV3 ? null : parseInviteKey(invite.data.inviteKey);
      if (!parsedV3 && !parsedLegacy) throw new Error("expected invite");
      const serverId = parsedV3?.payload.serverId ?? parsedLegacy!.serverId;
      const secret = parsedV3 ? Buffer.from(parsedV3.payload.inviteSecret, "base64url") : parsedLegacy!.secret;
      const seed = Buffer.alloc(32, 77);
      const expected = { sessionId: "S".repeat(32), serverId, hostId: "primary-host" };
      const proof = createSignedIceAccessProof({
        ...expected,
        identityId: "new-member",
        deviceSeed: seed,
        inviteAccessHash: sha256Hex(secret),
      }, expected.sessionId);
      expect(service.authorizeIceAccess(proof, expected)).toBe(true);
      expect(service.authorizeIceAccess({ ...proof, signature: "A".repeat(86) }, expected)).toBe(false);
      expect(service.authorizeIceAccess(proof, { ...expected, sessionId: "X".repeat(32) })).toBe(false);
      expect(service.joinByInvite("new-member", "Member", invite.data.inviteKey, ed25519PublicKey(seed).toString("base64url")).ok).toBe(true);
      const memberProof = createSignedIceAccessProof({ ...expected, identityId: "new-member", deviceSeed: seed }, "M".repeat(32));
      expect(service.authorizeIceAccess(memberProof, { ...expected, sessionId: "M".repeat(32) })).toBe(true);
      const strangerProof = createSignedIceAccessProof({ ...expected, identityId: "stranger", deviceSeed: Buffer.alloc(32, 78), inviteAccessHash: proof.payload.inviteAccessHash }, "N".repeat(32));
      expect(service.authorizeIceAccess(strangerProof, { ...expected, sessionId: "N".repeat(32) })).toBe(false);
    } finally {
      store.close();
    }
  });
  it("requires a one-shot capability from an already-linked device to enroll another device", () => {
    const { service, store } = serviceFixture();
    try {
      const attackerKey = ed25519PublicKey(Buffer.alloc(32, 41)).toString("base64url");
      const otherKey = ed25519PublicKey(Buffer.alloc(32, 42)).toString("base64url");
      const invite = service.inviteCreate("owner", "role-member", 1);
      expect(invite.ok).toBe(true);
      if (!invite.ok) return;

      expect(service.enrollDevice("owner", attackerKey, invite.data.inviteKey))
        .toMatchObject({ ok: false, error: { code: "unauthorized" } });
      expect(service.isAuthorizedDevice("owner", attackerKey)).toBe(false);
      expect(service.authorizeDeviceLink("owner", attackerKey, otherKey))
        .toMatchObject({ ok: false, error: { code: "unauthorized" } });

      const ownerKey = process.env.JC_OWNER_PUBLIC_KEY!;
      const authorized = service.authorizeDeviceLink("owner", ownerKey, attackerKey, 60_000);
      expect(authorized.ok).toBe(true);
      if (!authorized.ok) return;
      expect(service.enrollDevice("owner", otherKey, authorized.data.capability))
        .toMatchObject({ ok: false, error: { code: "unauthorized" } });
      expect(service.enrollDevice("owner", attackerKey, authorized.data.capability))
        .toEqual({ ok: true, data: { enrolled: true } });
      expect(service.isAuthorizedDevice("owner", attackerKey)).toBe(true);
      expect(service.enrollDevice("owner", attackerKey, authorized.data.capability))
        .toMatchObject({ ok: false, error: { code: "unauthorized" } });
    } finally {
      store.close();
    }
  });

  it("preserves replica-local enrollment and witness anchors atomically across snapshot sync and restart", () => {
    const primary = serviceFixture();
    const replica = serviceFixture(true);
    try {
      replica.store.raw.prepare(
        "INSERT INTO server_meta (key, value) VALUES ('replica_enrollment_id', ?)",
      ).run("enrollment-local-1");
      replica.store.raw.prepare(
        "INSERT INTO server_meta (key, value) VALUES ('replica_fenced_grant_id', ?)",
      ).run("grant-fenced-local-1");
      replica.service.configureReplicaTrust("known-primary", ["bridge-a", "bridge-b"]);
      const localRegistration = replica.service.createPrimaryRegistration("wss://replica.example/signal");
      expect(localRegistration.ok).toBe(true);
      if (!localRegistration.ok) return;
      expect(replica.service.commitPrimaryRegistration(localRegistration.data.recordHash)).toEqual({ ok: true, data: null });
      primary.store.appendOp({ type: "snapshotTestMutation" });
      const snapshot = primary.store.consistentSnapshot();
      expect(replica.service.applyReplicaSnapshot({
        dbB64: snapshot.encryptedDb.toString("base64"),
        serverId: snapshot.serverId,
        authorityPublicKey: snapshot.authorityPublicKey,
        epoch: snapshot.epoch,
        seq: snapshot.seq,
      })).toEqual({ ok: true, data: { epoch: snapshot.epoch, seq: snapshot.seq } });

      const preserved = replica.store.raw.prepare(
        "SELECT key, value FROM server_meta WHERE key IN ('replica_enrollment_id', 'replica_primary_host_id', 'replica_witness_bridge_ids', 'replica_fenced_grant_id') ORDER BY key",
      ).all() as { key: string; value: string }[];
      expect(Object.fromEntries(preserved.map((row) => [row.key, row.value]))).toEqual({
        replica_enrollment_id: "enrollment-local-1",
        replica_fenced_grant_id: "grant-fenced-local-1",
        replica_primary_host_id: "known-primary",
        replica_witness_bridge_ids: JSON.stringify(["bridge-a", "bridge-b"]),
      });

      expect(replica.service.applyReplicaSnapshot({
        dbB64: "not-canonical-base64",
        serverId: snapshot.serverId,
        authorityPublicKey: snapshot.authorityPublicKey,
        epoch: snapshot.epoch,
        seq: snapshot.seq,
      })).toMatchObject({ ok: false, error: { code: "conflict" } });
      const afterRejectedReplacement = replica.store.raw.prepare(
        "SELECT key, value FROM server_meta WHERE key IN ('replica_enrollment_id', 'replica_fenced_grant_id') ORDER BY key",
      ).all() as { key: string; value: string }[];
      expect(Object.fromEntries(afterRejectedReplacement.map((row) => [row.key, row.value]))).toEqual({
        replica_enrollment_id: "enrollment-local-1",
        replica_fenced_grant_id: "grant-fenced-local-1",
      });
      expect(replica.service.registrationChain()).toEqual([
        expect.objectContaining({ recordSeq: 1, recordHash: localRegistration.data.recordHash }),
      ]);

      replica.store.close();
      const reopened = new Store(replica.file, replica.key);
      try {
        const anchors = reopened.raw.prepare(
          "SELECT key, value FROM server_meta WHERE key IN ('replica_enrollment_id', 'replica_fenced_grant_id') ORDER BY key",
        ).all() as { key: string; value: string }[];
        expect(Object.fromEntries(anchors.map((row) => [row.key, row.value]))).toEqual({
          replica_enrollment_id: "enrollment-local-1",
          replica_fenced_grant_id: "grant-fenced-local-1",
        });
        const chain = reopened.raw.prepare(
          "SELECT record_seq, record_hash FROM host_record_chains WHERE record_hash = ?",
        ).all(localRegistration.data.recordHash) as { record_seq: number; record_hash: string }[];
        expect(chain).toEqual([{ record_seq: 1, record_hash: localRegistration.data.recordHash }]);
      } finally {
        reopened.close();
      }
    } finally {
      primary.store.close();
      try {
        replica.store.close();
      } catch {
        // The restart assertion may already have closed the original connection.
      }
    }
  });

  it("fails bridge witness promotion closed without strict quorum or when any bridge sees primary online", () => {
    expect(strictBridgeWitnessQuorum(1, [false])).toBe(false);
    expect(strictBridgeWitnessQuorum(1, [null])).toBe(false);
    expect(strictBridgeWitnessQuorum(2, [false, false])).toBe(true);
    expect(strictBridgeWitnessQuorum(2, [false, null])).toBe(false);
    expect(strictBridgeWitnessQuorum(3, [false, false, null])).toBe(true);
    expect(strictBridgeWitnessQuorum(3, [false, false, true])).toBe(false);
  });

  it("persists the full signed record hash and chains seq1 to seq2", () => {
    const { service, store } = serviceFixture();
    try {
      const first = service.createPrimaryRegistration("wss://bridge-one.example/signaling");
      expect(first.ok).toBe(true);
      if (!first.ok) return;
      expect(first.data.registration.record.payload.recordSeq).toBe(1);
      expect(service.commitPrimaryRegistration(first.data.recordHash)).toEqual({ ok: true, data: null });

      const persisted = store.raw.prepare("SELECT value FROM server_meta WHERE key = ?")
        .get(`host_record_hash:${first.data.registration.record.payload.hostId}`) as { value: string };
      expect(persisted.value).toBe(hostRegistrationRecordHash(first.data.registration.record));

      service.abandonPrimaryRegistration(first.data.recordHash);
      const second = service.createPrimaryRegistration("wss://bridge-two.example/signaling");
      expect(second.ok).toBe(true);
      if (!second.ok) return;
      expect(second.data.registration.record.payload.recordSeq).toBe(2);
      expect(second.data.registration.record.payload.previousRecordHash).toBe(first.data.recordHash);
    } finally {
      store.close();
    }
  });

  it("does not fence a writer for an uncertified or non-contiguous higher epoch", () => {
    const { service, store } = serviceFixture();
    try {
      const first = service.createPrimaryRegistration("wss://bridge-one.example/signaling");
      if (!first.ok) throw new Error(first.error.message);
      expect(service.commitPrimaryRegistration(first.data.recordHash)).toEqual({ ok: true, data: null });
      service.abandonPrimaryRegistration(first.data.recordHash);
      const base = first.data.registration.record.payload;
      const candidate = (epoch: number) => ({
        authorityPublicKey: first.data.registration.authorityPublicKey,
        grant: first.data.registration.grant,
        record: createSignedHostRecord({
          ...base,
          epoch,
          recordSeq: 2,
          previousRecordHash: first.data.recordHash,
          issuedAt: Date.now(),
          expiresAt: Date.now() + 60_000,
        }, Buffer.from(process.env.JC_HOST_SIGNING_SEED!, "hex")),
      });
      expect(service.observeHigherEpoch(candidate(1))).toBe(false);
      expect(service.observeHigherEpoch(candidate(42))).toBe(false);
      expect(service.getEpochPublic()).toBe(0);
      expect(service.isWriter()).toBe(true);
    } finally {
      store.close();
    }
  });

  it("rejects a forged second promotion witness outside the authority-approved bridge set", () => {
    const now = Date.now();
    const authoritySeed = Buffer.alloc(32, 51);
    const candidateSeed = Buffer.alloc(32, 52);
    const bridgeSeeds = [Buffer.alloc(32, 53), Buffer.alloc(32, 54)];
    const fakeBridgeSeed = Buffer.alloc(32, 55);
    const bridgeId = (seed: Buffer) => `ed25519:${ed25519Fingerprint(ed25519PublicKey(seed))}`;
    const descriptors = bridgeSeeds.map((seed, index) => createSignedBridgeDescriptor({
      version: 1,
      bridgeId: bridgeId(seed),
      endpoints: [`wss://bridge-${index}.example/rendezvous`],
      issuedAt: now - 1_000,
      expiresAt: now + 60_000,
    }, seed));
    process.env.JC_BRIDGE_DESCRIPTORS = JSON.stringify(descriptors);
    const grant = createSignedHostGrant({
      version: 1,
      grantId: "22222222-2222-4222-8222-222222222222",
      serverId: "11111111-1111-4111-8111-111111111111",
      issuerIdentityId: "owner",
      subjectIdentityId: "candidate",
      subjectAuthPublicKey: ed25519PublicKey(candidateSeed).toString("base64url"),
      devicePublicKey: ed25519PublicKey(candidateSeed).toString("base64url"),
      hostId: "candidate-host",
      capabilities: ["register", "replicate", "promote"],
      witnessBridgeIds: descriptors.map((descriptor) => descriptor.payload.bridgeId),
      generation: 1,
      issuedAt: now - 1_000,
      expiresAt: now + 60_000,
    }, authoritySeed);
    const record = createSignedHostRecord({
      version: 1,
      serverId: grant.payload.serverId,
      grantId: grant.payload.grantId,
      hostId: grant.payload.hostId,
      role: "primary",
      epoch: 1,
      recordSeq: 1,
      previousRecordHash: null,
      endpoints: ["wss://candidate.example/signaling"],
      candidates: [],
      issuedAt: now,
      ttlMs: 60_000,
      expiresAt: now + 60_000,
    }, candidateSeed);
    const expected = { primaryHostId: "old-primary", primaryRecordHash: "ab".repeat(32), primaryEpoch: 0 };
    const receipt = (seed: Buffer, requestId: string) => {
      const payload = {
        version: 1,
        bridgeId: bridgeId(seed),
        requestId,
        serverId: grant.payload.serverId,
        candidateHostId: grant.payload.hostId,
        primaryHostId: expected.primaryHostId,
        primaryRecordHash: expected.primaryRecordHash,
        primaryEpoch: 0,
        electionEpoch: 1,
        voteGrantedAt: now - 100,
        issuedAt: now,
        expiresAt: now + 5_000,
      };
      return {
        payload,
        publicKey: ed25519PublicKey(seed).toString("base64url"),
        signature: signCanonicalPayload(seed, "janjacord.promotion-vote.v1", payload).toString("base64url"),
      };
    };
    const candidate = { authorityPublicKey: ed25519PublicKey(authoritySeed).toString("base64url"), grant, record };
    expect(validObservedPromotionCertificate(
      [receipt(bridgeSeeds[0]!, "request-a"), receipt(bridgeSeeds[1]!, "request-b")], candidate, expected, now,
    )).toBe(true);
    expect(validObservedPromotionCertificate(
      [receipt(bridgeSeeds[0]!, "request-a"), receipt(fakeBridgeSeed, "request-fake")], candidate, expected, now,
    )).toBe(false);
  });

  it("promotes only through fresh 2/2 observations bound to enrolled primary and active grant", () => {
    const { service, store } = serviceFixture(true);
    try {
      const registration = service.createPrimaryRegistration("wss://bridge.example/signaling");
      expect(registration.ok).toBe(true);
      if (!registration.ok) return;
      const grant = registration.data.registration.grant;
      const ownerPublicKey = process.env.JC_OWNER_PUBLIC_KEY!;
      service.configureReplicaTrust("known-primary", ["bridge-a", "bridge-b"]);
      const observedAt = Date.now();
      let promotedEvent: { epoch: number } | null = null;
      service.events.once("writerPromoted", (event) => { promotedEvent = event as { epoch: number }; });
      const observation = (bridgeId: string, primaryHostId = "known-primary") => ({
        bridgeId, requestId: `request-${bridgeId}`, primaryHostId,
        candidateHostId: grant.payload.hostId,
        primaryRecordHash: "ab".repeat(32), primaryEpoch: 0, electionEpoch: 1,
        primaryOnline: false as const, observedAt, expiresAt: observedAt + 5_000, receipt: { bridgeId },
      });
      expect(service.promoteFromWitness("owner", ownerPublicKey, grant.payload.grantId, 0, [observation("bridge-a")]))
        .toMatchObject({ ok: false, error: { code: "forbidden" } });
      expect(service.promoteFromWitness("owner", ownerPublicKey, grant.payload.grantId, 0, [
        observation("bridge-a", "caller-selected"), observation("bridge-b", "caller-selected"),
      ])).toMatchObject({ ok: false, error: { code: "forbidden" } });
      expect(service.promoteFromWitness("owner", ownerPublicKey, grant.payload.grantId, 0, [
        { ...observation("bridge-a"), candidateHostId: "other-candidate" }, observation("bridge-b"),
      ])).toMatchObject({ ok: false, error: { code: "forbidden" } });
      expect(service.promoteFromWitness("owner", ownerPublicKey, grant.payload.grantId, 0, [
        observation("bridge-a"), observation("bridge-b"),
      ])).toEqual({ ok: true, data: { epoch: 1 } });
      expect(promotedEvent).toEqual({ epoch: 1 });
      expect(service.isWriter()).toBe(true);
    } finally {
      store.close();
    }
  });

  it("keeps a connectivity-fenced primary read-only after restart", () => {
    const { service, store, file, key } = serviceFixture();
    expect(service.isWriter()).toBe(true);
    expect(service.fencePrimaryWriter()).toBe(true);
    store.close();
    const restarted = reopenService(file, key);
    try {
      expect(restarted.service.isWriter()).toBe(false);
    } finally {
      restarted.store.close();
    }
  });

  it("restarts a persisted primary read-only and resumes only after explicit current registration quorum", () => {
    const { service, store, file, key } = serviceFixture();
    expect(service.isWriter()).toBe(true);
    const descriptors = configuredBridgeDescriptors();
    const bridgeIds = descriptors.map((descriptor) => descriptor.payload.bridgeId).sort();
    process.env.JC_BRIDGE_DESCRIPTORS = JSON.stringify(descriptors);
    store.close();

    const restarted = reopenService(file, key);
    try {
      expect(restarted.service.isWriter()).toBe(false);
      expect(restarted.service.isWriterResumePending()).toBe(true);
      expect(restarted.service.canAcceptCommand("server.updateConfig")).toBe(false);

      const registration = restarted.service.createPrimaryRegistration([
        "wss://restart-bridge-0.example/signaling",
        "wss://restart-bridge-1.example/signaling",
      ]);
      if (!registration.ok) throw new Error(registration.error.message);
      expect(registration.data.registration.record.payload.role).toBe("primary");
      expect(restarted.service.commitPrimaryRegistration(registration.data.recordHash))
        .toEqual({ ok: true, data: null });
      const binding = {
        recordHash: registration.data.recordHash,
        epoch: registration.data.registration.record.payload.epoch,
        role: registration.data.registration.record.payload.role,
      };

      expect(restarted.service.resumeWriterAfterRegistrationQuorum(binding, [bridgeIds[0]!], bridgeIds)).toBe(false);
      expect(restarted.service.isWriter()).toBe(false);
      expect(restarted.service.resumeWriterAfterRegistrationQuorum(
        binding,
        [bridgeIds[0]!, "unconfigured-bridge"],
        bridgeIds,
      )).toBe(false);
      expect(restarted.service.resumeWriterAfterRegistrationQuorum(binding, bridgeIds, bridgeIds)).toBe(true);
      expect(restarted.service.isWriter()).toBe(true);
      expect(restarted.service.isWriterResumePending()).toBe(false);
      expect(restarted.service.canAcceptCommand("server.updateConfig")).toBe(true);
    } finally {
      restarted.store.close();
    }
  });

  it("preserves the historical witness floor across 3->2->1 restarts so an old 3-bridge replica is the only possible writer", () => {
    const primary = serviceFixture();
    const descriptors = configuredBridgeDescriptors(3);
    const bridgeIds = descriptors.map((descriptor) => descriptor.payload.bridgeId).sort();
    let primaryHostId = "";
    let primaryRecordHash = "";

    const resume = (
      file: string,
      key: Buffer,
      currentDescriptors: typeof descriptors,
      acknowledgedBridgeIds: string[],
      expected: boolean,
    ) => {
      process.env.JC_BRIDGE_DESCRIPTORS = JSON.stringify(currentDescriptors);
      const restarted = reopenService(file, key);
      expect(restarted.service.isWriter()).toBe(false);
      expect(restarted.service.isWriterResumePending()).toBe(true);
      const registration = restarted.service.createPrimaryRegistration(
        currentDescriptors.map((descriptor) => descriptor.payload.endpoints[0]!.replace("/rendezvous", "/signaling")),
      );
      if (!registration.ok) throw new Error(registration.error.message);
      primaryHostId ||= registration.data.registration.record.payload.hostId;
      primaryRecordHash ||= registration.data.recordHash;
      expect(restarted.service.commitPrimaryRegistration(registration.data.recordHash)).toEqual({ ok: true, data: null });
      expect(restarted.service.resumeWriterAfterRegistrationQuorum({
        recordHash: registration.data.recordHash,
        epoch: registration.data.registration.record.payload.epoch,
        role: registration.data.registration.record.payload.role,
      }, acknowledgedBridgeIds, currentDescriptors.map((descriptor) => descriptor.payload.bridgeId).sort())).toBe(expected);
      expect(restarted.service.isWriter()).toBe(expected);
      return restarted;
    };

    primary.store.close();
    const allThree = resume(primary.file, primary.key, descriptors, bridgeIds.slice(0, 2), true);
    allThree.store.close();

    const remainingTwo = descriptors.slice(1);
    const remainingTwoIds = remainingTwo.map((descriptor) => descriptor.payload.bridgeId).sort();
    const twoBridgePrimary = resume(primary.file, primary.key, remainingTwo, remainingTwoIds, true);
    twoBridgePrimary.store.close();

    const finalDescriptor = descriptors.slice(2);
    const finalBridgeId = finalDescriptor[0]!.payload.bridgeId;
    const oneBridgePrimary = resume(primary.file, primary.key, finalDescriptor, [finalBridgeId], false);
    oneBridgePrimary.store.close();

    // The monotonic floor itself survives another process restart after the failed 1/1 attempt.
    const oneBridgeRestarted = resume(primary.file, primary.key, finalDescriptor, [finalBridgeId], false);
    try {
      const replica = serviceFixture(true);
      try {
        const candidate = replica.service.createPrimaryRegistration("wss://replica.example/signaling");
        if (!candidate.ok) throw new Error(candidate.error.message);
        const grant = candidate.data.registration.grant;
        replica.service.configureReplicaTrust(primaryHostId, bridgeIds);
        const observedAt = Date.now();
        const observation = (bridgeId: string) => ({
          bridgeId,
          requestId: `old-set-${bridgeId}`,
          candidateHostId: grant.payload.hostId,
          primaryHostId,
          primaryRecordHash,
          primaryEpoch: 0,
          electionEpoch: 1,
          primaryOnline: false as const,
          observedAt,
          expiresAt: observedAt + 5_000,
          receipt: { bridgeId },
        });
        expect(replica.service.promoteFromWitness(
          "owner",
          process.env.JC_OWNER_PUBLIC_KEY!,
          grant.payload.grantId,
          0,
          [observation(bridgeIds[0]!), observation(bridgeIds[1]!)],
        )).toEqual({ ok: true, data: { epoch: 1 } });
        expect(Number(oneBridgeRestarted.service.isWriter()) + Number(replica.service.isWriter())).toBe(1);
      } finally {
        replica.store.close();
      }
    } finally {
      oneBridgeRestarted.store.close();
    }
  });

  it("keeps the historical floor from a subsequently revoked promote grant during R5 writer-state migration", () => {
    const { service, store, file, key } = serviceFixture();
    const current = service.createPrimaryRegistration("wss://primary.example/signaling");
    if (!current.ok) throw new Error(current.error.message);
    const descriptors = configuredBridgeDescriptors(3);
    const historicalBridgeIds = descriptors.map((descriptor) => descriptor.payload.bridgeId).sort();
    const now = Date.now();
    const replicaSeed = Buffer.alloc(32, 89);
    const replicaGrant = createSignedHostGrant({
      version: 1,
      grantId: randomUUID(),
      serverId: current.data.registration.record.payload.serverId,
      issuerIdentityId: "owner",
      subjectIdentityId: "owner",
      subjectAuthPublicKey: process.env.JC_OWNER_PUBLIC_KEY!,
      devicePublicKey: ed25519PublicKey(replicaSeed).toString("base64url"),
      hostId: "r5-enrolled-replica",
      capabilities: ["register", "replicate", "promote"],
      witnessBridgeIds: historicalBridgeIds,
      generation: 1,
      issuedAt: now - 1_000,
      expiresAt: now + 60_000,
    }, Buffer.alloc(32, 11));
    store.raw.prepare(
      "INSERT INTO host_grants (grant_id, subject_identity_id, host_id, subject_auth_public_key, device_public_key, capabilities, payload, signature, expires_at, created_at, accepted_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
    ).run(
      replicaGrant.payload.grantId,
      "owner",
      replicaGrant.payload.hostId,
      replicaGrant.payload.subjectAuthPublicKey,
      replicaGrant.payload.devicePublicKey,
      JSON.stringify(replicaGrant.payload.capabilities),
      JSON.stringify(replicaGrant.payload),
      replicaGrant.signature,
      replicaGrant.payload.expiresAt,
      now - 1_000,
      now - 500,
    );
    store.raw.prepare(
      `INSERT INTO replica_enrollments
       (enrollment_id, grant_id, generation, snapshot_hash, epoch, seq, issued_at, expires_at, consumed_at)
       VALUES (?,?,?,?,?,?,?,?,?)`,
    ).run(randomUUID(), replicaGrant.payload.grantId, 1, "ab".repeat(32), 0, 0, now - 500, now + 60_000, now - 500);
    expect(service.hostGrantRevoke("owner", replicaGrant.payload.grantId, "retired after enrollment").ok).toBe(true);
    store.raw.prepare("UPDATE server_meta SET value = ? WHERE key = ?").run(JSON.stringify({
      version: 1,
      state: "writer",
      hostId: current.data.registration.record.payload.hostId,
      grantId: current.data.registration.record.payload.grantId,
      epoch: 0,
      updatedAt: now,
    }), `writer_state:${current.data.registration.record.payload.hostId}`);
    service.abandonPrimaryRegistration(current.data.recordHash);
    process.env.JC_BRIDGE_DESCRIPTORS = JSON.stringify(descriptors.slice(2));
    store.close();

    const restarted = reopenService(file, key);
    try {
      expect(restarted.service.isWriter()).toBe(false);
      expect(restarted.service.isWriterResumePending()).toBe(true);
      const registration = restarted.service.createPrimaryRegistration("wss://restart-bridge-2.example/signaling");
      if (!registration.ok) throw new Error(registration.error.message);
      expect(restarted.service.commitPrimaryRegistration(registration.data.recordHash)).toEqual({ ok: true, data: null });
      const finalBridgeId = descriptors[2]!.payload.bridgeId;
      expect(restarted.service.resumeWriterAfterRegistrationQuorum({
        recordHash: registration.data.recordHash,
        epoch: registration.data.registration.record.payload.epoch,
        role: registration.data.registration.record.payload.role,
      }, [finalBridgeId], [finalBridgeId])).toBe(false);
      const persisted = restarted.store.raw.prepare("SELECT value FROM server_meta WHERE key = ?")
        .get(`writer_state:${registration.data.registration.record.payload.hostId}`) as { value: string };
      expect(JSON.parse(persisted.value)).toMatchObject({
        version: 2,
        state: "writer",
        witnessHistoryComplete: true,
        witnessBridgeSets: expect.arrayContaining([historicalBridgeIds]),
      });
    } finally {
      restarted.store.close();
    }
  });

  it("migrates a zero-bridge replica enrollment from writer state v1 to v2 without fencing restart", () => {
    const { service, store, file, key } = serviceFixture();
    const seeded = seedLegacyWriterWithReplicaEnrollment(service, store, "zero-bridge");
    store.close();

    const restarted = reopenService(file, key);
    try {
      expect(restarted.service.isWriter()).toBe(true);
      expect(restarted.service.isWriterResumePending()).toBe(false);
      expect(restarted.service.canAcceptCommand("server.updateConfig")).toBe(true);
      const persisted = restarted.store.raw.prepare("SELECT value FROM server_meta WHERE key = ?")
        .get(seeded.writerStateKey) as { value: string };
      expect(JSON.parse(persisted.value)).toMatchObject({
        version: 2,
        state: "writer",
        witnessHistoryComplete: true,
        witnessBridgeSets: [],
      });
    } finally {
      restarted.store.close();
    }
  });

  it("keeps a one-bridge non-promotable enrollment operable across writer restart", () => {
    const { service, store, file, key } = serviceFixture();
    process.env.JC_BRIDGE_DESCRIPTORS = JSON.stringify(configuredBridgeDescriptors(1));
    const seeded = seedLegacyWriterWithReplicaEnrollment(service, store, "one-bridge");
    store.close();

    const restarted = reopenService(file, key);
    try {
      expect(restarted.service.isWriter()).toBe(true);
      expect(restarted.service.isWriterResumePending()).toBe(false);
      const persisted = restarted.store.raw.prepare("SELECT value FROM server_meta WHERE key = ?")
        .get(seeded.writerStateKey) as { value: string };
      expect(JSON.parse(persisted.value)).toMatchObject({
        version: 2,
        witnessHistoryComplete: true,
        witnessBridgeSets: [],
      });
    } finally {
      restarted.store.close();
    }
  });

  it("does not fence writer migration when a replicate-only two-witness enrollment is reduced 2->1", () => {
    const { service, store, file, key } = serviceFixture();
    const descriptors = configuredBridgeDescriptors(2);
    const historicalBridgeIds = descriptors.map((descriptor) => descriptor.payload.bridgeId).sort();
    const seeded = seedLegacyWriterWithReplicaEnrollment(service, store, "replicate-only-2-to-1", {
      capabilities: ["replicate"],
      witnessBridgeIds: historicalBridgeIds,
    });
    process.env.JC_BRIDGE_DESCRIPTORS = JSON.stringify(descriptors.slice(1));
    store.close();

    const restarted = reopenService(file, key);
    try {
      expect(restarted.service.isWriter()).toBe(true);
      expect(restarted.service.isWriterResumePending()).toBe(false);
      expect(restarted.service.canAcceptCommand("server.updateConfig")).toBe(true);
      const persisted = restarted.store.raw.prepare("SELECT value FROM server_meta WHERE key = ?")
        .get(seeded.writerStateKey) as { value: string };
      expect(JSON.parse(persisted.value)).toMatchObject({
        version: 2,
        state: "writer",
        witnessHistoryComplete: true,
        witnessBridgeSets: [],
      });
    } finally {
      restarted.store.close();
    }
  });

  it("does not fence writer migration when a replicate-only two-witness enrollment is reduced 2->0", () => {
    const { service, store, file, key } = serviceFixture();
    const descriptors = configuredBridgeDescriptors(2);
    const historicalBridgeIds = descriptors.map((descriptor) => descriptor.payload.bridgeId).sort();
    const seeded = seedLegacyWriterWithReplicaEnrollment(service, store, "replicate-only-2-to-0", {
      capabilities: ["replicate"],
      witnessBridgeIds: historicalBridgeIds,
    });
    store.close();

    const restarted = reopenService(file, key);
    try {
      expect(restarted.service.isWriter()).toBe(true);
      expect(restarted.service.isWriterResumePending()).toBe(false);
      expect(restarted.service.canAcceptCommand("server.updateConfig")).toBe(true);
      const persisted = restarted.store.raw.prepare("SELECT value FROM server_meta WHERE key = ?")
        .get(seeded.writerStateKey) as { value: string };
      expect(JSON.parse(persisted.value)).toMatchObject({
        version: 2,
        state: "writer",
        witnessHistoryComplete: true,
        witnessBridgeSets: [],
      });
    } finally {
      restarted.store.close();
    }
  });

  it("does not let a revoked zero-bridge replica enrollment poison writer restart", () => {
    const { service, store, file, key } = serviceFixture();
    const seeded = seedLegacyWriterWithReplicaEnrollment(service, store, "revoked-zero-bridge");
    expect(service.hostGrantRevoke("owner", seeded.replicaGrantId, "retired").ok).toBe(true);
    store.close();

    const restarted = reopenService(file, key);
    try {
      expect(restarted.service.isWriter()).toBe(true);
      expect(restarted.service.canAcceptCommand("server.updateConfig")).toBe(true);
      const persisted = restarted.store.raw.prepare("SELECT value FROM server_meta WHERE key = ?")
        .get(seeded.writerStateKey) as { value: string };
      expect(JSON.parse(persisted.value)).toMatchObject({
        version: 2,
        witnessHistoryComplete: true,
        witnessBridgeSets: [],
      });
    } finally {
      restarted.store.close();
    }
  });

  it.each(["invalid-signature", "malformed-json", "malformed-witness-set"] as const)(
    "keeps writer restart fail-closed for a %s replica enrollment grant",
    (corruption) => {
      const { service, store, file, key } = serviceFixture();
      const seeded = seedLegacyWriterWithReplicaEnrollment(service, store, corruption);
      if (corruption === "invalid-signature") {
        store.raw.prepare("UPDATE host_grants SET signature = ? WHERE grant_id = ?")
          .run("A".repeat(86), seeded.replicaGrantId);
      } else if (corruption === "malformed-json") {
        store.raw.prepare("UPDATE host_grants SET payload = ? WHERE grant_id = ?")
          .run("{", seeded.replicaGrantId);
      } else {
        const row = store.raw.prepare("SELECT payload FROM host_grants WHERE grant_id = ?")
          .get(seeded.replicaGrantId) as { payload: string };
        const payload = JSON.parse(row.payload) as Record<string, unknown>;
        payload.witnessBridgeIds = ["single-invalid-witness"];
        store.raw.prepare("UPDATE host_grants SET payload = ? WHERE grant_id = ?")
          .run(JSON.stringify(payload), seeded.replicaGrantId);
      }
      store.close();

      const restarted = reopenService(file, key);
      try {
        expect(restarted.service.isWriter()).toBe(false);
        expect(restarted.service.isWriterResumePending()).toBe(false);
        expect(restarted.service.canAcceptCommand("server.updateConfig")).toBe(false);
        const persisted = restarted.store.raw.prepare("SELECT value FROM server_meta WHERE key = ?")
          .get(seeded.writerStateKey) as { value: string };
        expect(JSON.parse(persisted.value)).toMatchObject({
          version: 2,
          witnessHistoryComplete: false,
        });
      } finally {
        restarted.store.close();
      }
    },
  );

  it("migrates an existing bridged community without writer state fail-closed until current quorum", () => {
    const { service, store, file, key } = serviceFixture();
    expect(service.isWriter()).toBe(true);
    const descriptors = configuredBridgeDescriptors();
    const bridgeIds = descriptors.map((descriptor) => descriptor.payload.bridgeId).sort();
    process.env.JC_BRIDGE_DESCRIPTORS = JSON.stringify(descriptors);
    store.raw.prepare("DELETE FROM server_meta WHERE key LIKE 'writer_state:%'").run();
    store.close();

    const restarted = reopenService(file, key);
    try {
      expect(restarted.service.isWriter()).toBe(false);
      expect(restarted.service.isWriterResumePending()).toBe(true);
      expect(restarted.service.canAcceptCommand("server.updateConfig")).toBe(false);
      const registration = restarted.service.createPrimaryRegistration([
        "wss://restart-bridge-0.example/signaling",
        "wss://restart-bridge-1.example/signaling",
      ]);
      if (!registration.ok) throw new Error(registration.error.message);
      expect(restarted.service.commitPrimaryRegistration(registration.data.recordHash)).toEqual({ ok: true, data: null });
      const binding = {
        recordHash: registration.data.recordHash,
        epoch: registration.data.registration.record.payload.epoch,
        role: registration.data.registration.record.payload.role,
      };
      expect(restarted.service.resumeWriterAfterRegistrationQuorum(binding, [bridgeIds[0]!], bridgeIds)).toBe(false);
      expect(restarted.service.resumeWriterAfterRegistrationQuorum(binding, bridgeIds, bridgeIds)).toBe(true);
      expect(restarted.service.canAcceptCommand("server.updateConfig")).toBe(true);
    } finally {
      restarted.store.close();
    }
  });

  it("clears restart resume eligibility when the suspended writer is fenced", () => {
    const { service, store, file, key } = serviceFixture();
    expect(service.isWriter()).toBe(true);
    const descriptors = configuredBridgeDescriptors();
    const bridgeIds = descriptors.map((descriptor) => descriptor.payload.bridgeId).sort();
    process.env.JC_BRIDGE_DESCRIPTORS = JSON.stringify(descriptors);
    store.close();

    const restarted = reopenService(file, key);
    try {
      const registration = restarted.service.createPrimaryRegistration([
        "wss://restart-bridge-0.example/signaling",
        "wss://restart-bridge-1.example/signaling",
      ]);
      if (!registration.ok) throw new Error(registration.error.message);
      expect(restarted.service.commitPrimaryRegistration(registration.data.recordHash)).toEqual({ ok: true, data: null });
      const binding = {
        recordHash: registration.data.recordHash,
        epoch: registration.data.registration.record.payload.epoch,
        role: registration.data.registration.record.payload.role,
      };
      expect(restarted.service.fencePrimaryWriter()).toBe(true);
      expect(restarted.service.isWriterResumePending()).toBe(false);
      expect(restarted.service.resumeWriterAfterRegistrationQuorum(binding, bridgeIds, bridgeIds)).toBe(false);
      expect(restarted.service.isWriter()).toBe(false);
    } finally {
      restarted.store.close();
    }
  });

  it("invalidates the persisted witness-floor resume path after a valid higher-epoch fence", () => {
    const { service, store, file, key } = serviceFixture();
    const descriptors = configuredBridgeDescriptors();
    const bridgeIds = descriptors.map((descriptor) => descriptor.payload.bridgeId).sort();
    process.env.JC_BRIDGE_DESCRIPTORS = JSON.stringify(descriptors);
    store.close();

    const restarted = reopenService(file, key);
    try {
      const current = restarted.service.createPrimaryRegistration(
        descriptors.map((descriptor) => descriptor.payload.endpoints[0]!.replace("/rendezvous", "/signaling")),
      );
      if (!current.ok) throw new Error(current.error.message);
      expect(restarted.service.commitPrimaryRegistration(current.data.recordHash)).toEqual({ ok: true, data: null });
      const oldBinding = {
        recordHash: current.data.recordHash,
        epoch: current.data.registration.record.payload.epoch,
        role: current.data.registration.record.payload.role,
      };
      expect(restarted.service.isWriterResumePending()).toBe(true);

      const now = Date.now();
      const authoritySeed = Buffer.alloc(32, 11);
      const candidateSeed = Buffer.alloc(32, 88);
      const candidateGrant = createSignedHostGrant({
        version: 1,
        grantId: randomUUID(),
        serverId: current.data.registration.record.payload.serverId,
        issuerIdentityId: "owner",
        subjectIdentityId: "owner",
        subjectAuthPublicKey: process.env.JC_OWNER_PUBLIC_KEY!,
        devicePublicKey: ed25519PublicKey(candidateSeed).toString("base64url"),
        hostId: "higher-epoch-candidate",
        capabilities: ["register", "replicate", "promote"],
        witnessBridgeIds: bridgeIds,
        generation: 1,
        issuedAt: now - 1_000,
        expiresAt: now + 60_000,
      }, authoritySeed);
      restarted.store.raw.prepare(
        "INSERT INTO host_grants (grant_id, subject_identity_id, host_id, subject_auth_public_key, device_public_key, capabilities, payload, signature, expires_at, created_at, accepted_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
      ).run(
        candidateGrant.payload.grantId,
        "owner",
        candidateGrant.payload.hostId,
        candidateGrant.payload.subjectAuthPublicKey,
        candidateGrant.payload.devicePublicKey,
        JSON.stringify(candidateGrant.payload.capabilities),
        JSON.stringify(candidateGrant.payload),
        candidateGrant.signature,
        candidateGrant.payload.expiresAt,
        now - 1_000,
        now - 500,
      );
      const candidateRecord = createSignedHostRecord({
        version: 1,
        serverId: candidateGrant.payload.serverId,
        grantId: candidateGrant.payload.grantId,
        hostId: candidateGrant.payload.hostId,
        role: "primary",
        epoch: 1,
        recordSeq: 1,
        previousRecordHash: null,
        endpoints: ["wss://higher-epoch.example/signaling"],
        candidates: [],
        issuedAt: now,
        ttlMs: 60_000,
        expiresAt: now + 60_000,
      }, candidateSeed);
      const bridgeSeeds = [Buffer.alloc(32, 71), Buffer.alloc(32, 72)];
      const receipt = (seed: Buffer, requestId: string) => {
        const bridgeId = `ed25519:${ed25519Fingerprint(ed25519PublicKey(seed))}`;
        const payload = {
          version: 1,
          bridgeId,
          requestId,
          serverId: candidateGrant.payload.serverId,
          candidateHostId: candidateGrant.payload.hostId,
          primaryHostId: current.data.registration.record.payload.hostId,
          primaryRecordHash: current.data.recordHash,
          primaryEpoch: 0,
          electionEpoch: 1,
          voteGrantedAt: now - 100,
          issuedAt: now,
          expiresAt: now + 5_000,
        };
        return {
          payload,
          publicKey: ed25519PublicKey(seed).toString("base64url"),
          signature: signCanonicalPayload(seed, "janjacord.promotion-vote.v1", payload).toString("base64url"),
        };
      };

      expect(restarted.service.observeHigherEpoch({
        authorityPublicKey: current.data.registration.authorityPublicKey,
        grant: candidateGrant,
        record: candidateRecord,
        promotionCertificate: [receipt(bridgeSeeds[0]!, "higher-a"), receipt(bridgeSeeds[1]!, "higher-b")],
      })).toBe(true);
      expect(restarted.service.getEpochPublic()).toBe(1);
      expect(restarted.service.isWriter()).toBe(false);
      expect(restarted.service.isWriterResumePending()).toBe(false);
      expect(restarted.service.resumeWriterAfterRegistrationQuorum(oldBinding, bridgeIds, bridgeIds)).toBe(false);
    } finally {
      restarted.store.close();
    }

    const fencedRestart = reopenService(file, key);
    try {
      expect(fencedRestart.service.getEpochPublic()).toBe(1);
      expect(fencedRestart.service.isWriter()).toBe(false);
      expect(fencedRestart.service.isWriterResumePending()).toBe(false);
    } finally {
      fencedRestart.store.close();
    }
  });

  it("restarts a witness-promoted host read-only until its current primary record reaches bridge quorum", () => {
    const { service, store, file, key } = serviceFixture(true);
    const registration = service.createPrimaryRegistration("wss://bridge.example/signaling");
    if (!registration.ok) throw new Error(registration.error.message);
    const descriptors = configuredBridgeDescriptors();
    const bridgeIds = descriptors.map((descriptor) => descriptor.payload.bridgeId).sort();
    service.configureReplicaTrust("known-primary", bridgeIds);
    const observedAt = Date.now();
    const promoted = service.promoteFromWitness(
      "owner",
      process.env.JC_OWNER_PUBLIC_KEY!,
      registration.data.registration.grant.payload.grantId,
      0,
      [
        { bridgeId: bridgeIds[0]!, requestId: "request-a", candidateHostId: registration.data.registration.record.payload.hostId, primaryHostId: "known-primary", primaryRecordHash: "ab".repeat(32), primaryEpoch: 0, electionEpoch: 1, primaryOnline: false, observedAt, expiresAt: observedAt + 5_000, receipt: { bridgeId: bridgeIds[0]! } },
        { bridgeId: bridgeIds[1]!, requestId: "request-b", candidateHostId: registration.data.registration.record.payload.hostId, primaryHostId: "known-primary", primaryRecordHash: "ab".repeat(32), primaryEpoch: 0, electionEpoch: 1, primaryOnline: false, observedAt, expiresAt: observedAt + 5_000, receipt: { bridgeId: bridgeIds[1]! } },
      ],
    );
    expect(promoted).toEqual({ ok: true, data: { epoch: 1 } });
    process.env.JC_BRIDGE_DESCRIPTORS = JSON.stringify(descriptors);
    store.close();
    const restarted = reopenService(file, key);
    try {
      expect(restarted.service.getEpochPublic()).toBe(1);
      expect(restarted.service.isWriter()).toBe(false);
      expect(restarted.service.isWriterResumePending()).toBe(true);
      const current = restarted.service.createPrimaryRegistration([
        "wss://restart-bridge-0.example/signaling",
        "wss://restart-bridge-1.example/signaling",
      ]);
      if (!current.ok) throw new Error(current.error.message);
      expect(current.data.registration.record.payload.role).toBe("primary");
      expect(current.data.registration.record.payload.epoch).toBe(1);
      expect(restarted.service.commitPrimaryRegistration(current.data.recordHash)).toEqual({ ok: true, data: null });
      expect(restarted.service.resumeWriterAfterRegistrationQuorum({
        recordHash: current.data.recordHash,
        epoch: current.data.registration.record.payload.epoch,
        role: current.data.registration.record.payload.role,
      }, bridgeIds, bridgeIds)).toBe(true);
      expect(restarted.service.isWriter()).toBe(true);
    } finally {
      restarted.store.close();
    }
  });

  it("rejects witness promotion after the local promote grant is revoked", () => {
    const { service, store } = serviceFixture(true);
    try {
      const registration = service.createPrimaryRegistration("wss://bridge.example/signaling");
      expect(registration.ok).toBe(true);
      if (!registration.ok) return;
      const grantId = registration.data.registration.grant.payload.grantId;
      expect(service.hostGrantRevoke("owner", grantId, "retired").ok).toBe(true);
      service.configureReplicaTrust("known-primary", ["bridge-a", "bridge-b"]);
      const observedAt = Date.now();
      expect(service.promoteFromWitness("owner", process.env.JC_OWNER_PUBLIC_KEY!, grantId, 0, [
        { bridgeId: "bridge-a", requestId: "request-a", candidateHostId: registration.data.registration.record.payload.hostId, primaryHostId: "known-primary", primaryRecordHash: "ab".repeat(32), primaryEpoch: 0, electionEpoch: 1, primaryOnline: false, observedAt, expiresAt: observedAt + 5_000, receipt: { bridgeId: "bridge-a" } },
        { bridgeId: "bridge-b", requestId: "request-b", candidateHostId: registration.data.registration.record.payload.hostId, primaryHostId: "known-primary", primaryRecordHash: "ab".repeat(32), primaryEpoch: 0, electionEpoch: 1, primaryOnline: false, observedAt, expiresAt: observedAt + 5_000, receipt: { bridgeId: "bridge-b" } },
      ])).toMatchObject({ ok: false, error: { code: "forbidden" } });
      expect(service.isWriter()).toBe(false);
    } finally {
      store.close();
    }
  });

  it("registers a member-owned candidate before owner grant, accept and sealed enrollment", () => {
    const { service, store } = serviceFixture();
    try {
      const memberSeed = Buffer.alloc(32, 31);
      const memberPublicKey = ed25519PublicKey(memberSeed).toString("base64url");
      const hostSeed = Buffer.alloc(32, 32);
      const hostPublicKey = ed25519PublicKey(hostSeed).toString("base64url");
      const x25519 = generateKeyPairSync("x25519");
      const enrollmentPublicKey = Buffer.from(x25519.publicKey.export({ format: "der", type: "spki" })).subarray(-32).toString("base64url");
      const invite = service.inviteCreate("owner", "role-member", 1);
      expect(invite.ok).toBe(true);
      if (!invite.ok) return;
      const joined = service.joinByInvite("member", "Member", invite.data.inviteKey, memberPublicKey);
      if (!joined.ok) throw new Error(`join failed: ${joined.error.code}: ${joined.error.message}`);
      expect(joined).toMatchObject({ ok: true });

      const common = {
        serverId: service.getServerId(),
        subjectIdentityId: "member",
        subjectAuthPublicKey: memberPublicKey,
        hostPublicKey,
        enrollmentPublicKey,
        hostId: "member-host",
      };
      const proof = (seed: Buffer, domain: string) => {
        const proofId = randomUUID();
        const issuedAt = Date.now();
        return { proofId, issuedAt, signature: signCanonicalPayload(seed, domain, { ...common, proofId, issuedAt }).toString("base64url") };
      };
      const deviceCandidateProof = proof(memberSeed, "janjacord.host-candidate-device.v1");
      const hostCandidateProof = proof(hostSeed, "janjacord.host-candidate-possession.v1");
      const candidate = service.hostCandidateRegister(
        "member", memberPublicKey, hostPublicKey, enrollmentPublicKey, "member-host",
        deviceCandidateProof,
        hostCandidateProof,
      );
      expect(candidate.ok).toBe(true);
      if (!candidate.ok) return;
      expect(service.hostCandidateRegister(
        "member", memberPublicKey, hostPublicKey, enrollmentPublicKey, "member-host",
        deviceCandidateProof, hostCandidateProof,
      )).toMatchObject({ ok: false, error: { code: "conflict" } });
      const candidateId = String((candidate.data.candidate as { candidateId: string }).candidateId);
      const grant = service.hostGrantCreate("owner", "member", candidateId, ["replicate", "promote"]);
      expect(grant.ok).toBe(true);
      if (!grant.ok) return;
      const signedGrant = grant.data.grant as { payload: { grantId: string } };
      const grantId = signedGrant.payload.grantId;
      const grantContext = {
        serverId: common.serverId,
        grantId,
        subjectIdentityId: common.subjectIdentityId,
        subjectAuthPublicKey: common.subjectAuthPublicKey,
        hostPublicKey: common.hostPublicKey,
        enrollmentPublicKey: common.enrollmentPublicKey,
      };
      const hostProof = (purpose: "accept" | "enroll") => {
        const proofId = randomUUID();
        const issuedAt = Date.now();
        return {
          proofId,
          issuedAt,
          signature: signCanonicalPayload(hostSeed, "janjacord.host-possession.v1", { purpose, ...grantContext, proofId, issuedAt }).toString("base64url"),
        };
      };
      const acceptanceProof = hostProof("accept");
      const accepted = service.hostGrantAccept("member", memberPublicKey, grantId, acceptanceProof);
      if (!accepted.ok) throw new Error(`accept failed: ${accepted.error.code}: ${accepted.error.message}`);
      expect(accepted.ok).toBe(true);
      expect(service.hostGrantAccept("member", memberPublicKey, grantId, acceptanceProof))
        .toMatchObject({ ok: false, error: { code: "conflict" } });
      const memberState = service.getState("member");
      expect(memberState.ok && memberState.data.hostCandidates).toEqual([
        expect.objectContaining({ candidateId, subjectIdentityId: "member", status: "accepted" }),
      ]);
      expect(memberState.ok && memberState.data.hostGrants).toEqual([
        expect.objectContaining({ grantId, subjectIdentityId: "member", status: "accepted" }),
      ]);
      expect(JSON.stringify(memberState)).not.toContain("sealedEnrollment");
      const enrollmentProof = hostProof("enroll");
      const enrollment = service.enrollReplica("member", memberPublicKey, grantId, enrollmentProof);
      expect(enrollment.ok).toBe(true);
      if (enrollment.ok) {
        expect(enrollment.data).toHaveProperty("sealedEnrollment.ciphertext");
        expect(JSON.stringify(enrollment.data)).not.toContain("dbKeyB64");
        expect(verifyReplicaEnrollmentTranscript(enrollment.data.sealedEnrollment)).not.toBeNull();
        const tampered = structuredClone(enrollment.data.sealedEnrollment);
        tampered.transcript.payload.seq++;
        expect(verifyReplicaEnrollmentTranscript(tampered)).toBeNull();
      }
      expect(service.enrollReplica("member", memberPublicKey, grantId, enrollmentProof))
        .toMatchObject({ ok: false, error: { code: "conflict" } });
      expect(service.enrollReplica("member", memberPublicKey, grantId, hostProof("enroll")))
        .toMatchObject({ ok: false, error: { code: "conflict" } });
      const listed = service.hostGrantList("owner");
      expect(listed.ok && (listed.data.candidates as unknown[]).length).toBe(1);
    } finally {
      store.close();
    }
  });

  it("falls back to a self-contained JC2 invite when no bridge descriptor exists", () => {
    const { service, store } = serviceFixture();
    try {
      const invite = service.inviteCreate("owner", "role-member", 1);
      expect(invite.ok).toBe(true);
      if (invite.ok) expect(invite.data.inviteKey.startsWith("JC2-")).toBe(true);
      const listed = service.inviteList("owner");
      expect(listed.ok && listed.data).toEqual([
        expect.objectContaining({ status: "active", maxUses: 1, used: 0 }),
      ]);
      const state = service.getState("owner");
      const ownerRole = state.ok
        ? (state.data.roles as { id: string; permissions: string[] }[]).find((role) => role.id === "role-owner")
        : undefined;
      expect(ownerRole?.permissions).toContain("manage_hosts");
      expect(ownerRole?.permissions).toContain("manage_invites");

      const memberSeed = Buffer.alloc(32, 71);
      if (!invite.ok) throw new Error("owner invite creation unexpectedly failed");
      const joined = service.joinByInvite(
        "invite-reader", "Reader", invite.data.inviteKey, ed25519PublicKey(memberSeed).toString("base64url"),
      );
      expect(joined.ok).toBe(true);
      expect(service.inviteList("invite-reader")).toMatchObject({ ok: false, error: { code: "forbidden" } });
    } finally {
      store.close();
    }
  });

  it("reserves aggregate attachment bytes before accepting chunks and includes the reservation in member quota", () => {
    const { service, store } = serviceFixture();
    try {
      const state = service.getState("owner");
      expect(state.ok).toBe(true);
      if (!state.ok) return;
      const channelId = (state.data.channels as { id: string }[])[0]!.id;
      const assetId = randomUUID();
      const ciphertext = Buffer.alloc(256, 7);
      const chunks = encodeAttachmentChunks(ciphertext);
      expect(service.attachmentUploadBegin("owner", assetId, channelId, ["owner"], ciphertext.length, 2, attachmentSha256(ciphertext)))
        .toMatchObject({ ok: false, error: { code: "invalid_input" } });
      expect(service.attachmentUploadBegin(
        "owner", assetId, channelId, ["owner"], ciphertext.length, chunks.length, attachmentSha256(ciphertext),
      )).toEqual({ ok: true, data: { receivedChunks: [] } });

      const config = service.getConfig();
      store.raw.prepare("UPDATE server_meta SET value = ? WHERE key = 'config'")
        .run(JSON.stringify({ ...config, maxSpoolBytes: 10_000, maxMemberSpoolBytes: 600 }));
      const envelope = buildEnvelope({
        serverId: service.getServerId(),
        channelId,
        sender: "owner",
        cryptoEpoch: 0,
        audience: { algo: "sha256", commitment: "", members: ["owner"] },
        ciphertext: Buffer.alloc(512, 9).toString("base64"),
        ordering: { seq: 1 },
      });
      expect(service.sendEnvelope("owner", envelope))
        .toMatchObject({ ok: false, error: { code: "rate_limited", message: "member spool quota exceeded" } });
    } finally {
      store.close();
    }
  });

  it("bounds pending attachment cardinality before allocating persistent transfer rows", () => {
    const { service, store } = serviceFixture();
    try {
      const state = service.getState("owner");
      if (!state.ok) throw new Error(state.error.message);
      const channelId = (state.data.channels as { id: string }[])[0]!.id;
      const accepted: string[] = [];
      for (let index = 0; index < MAX_PENDING_ATTACHMENT_TRANSFERS_PER_MEMBER; index += 1) {
        const assetId = randomUUID();
        accepted.push(assetId);
        expect(service.attachmentUploadBegin(
          "owner", assetId, channelId, ["owner"], 29, 1, index.toString(16).padStart(64, "0"),
        )).toEqual({ ok: true, data: { receivedChunks: [] } });
      }

      expect(service.attachmentUploadBegin(
        "owner", randomUUID(), channelId, ["owner"], 29, 1, "f".repeat(64),
      )).toMatchObject({ ok: false, error: { code: "rate_limited", message: "pending attachment transfer limit exceeded" } });
      expect(store.raw.prepare("SELECT COUNT(*) AS count FROM attachments").get())
        .toEqual({ count: MAX_PENDING_ATTACHMENT_TRANSFERS_PER_MEMBER });
      expect(store.raw.prepare("SELECT size_bytes FROM spool_usage WHERE scope_id = 'global'").get())
        .toEqual({ size_bytes: MAX_PENDING_ATTACHMENT_TRANSFERS_PER_MEMBER * 29 });

      expect(service.attachmentUploadAbort("owner", accepted[0]!)).toEqual({ ok: true, data: null });
      expect(service.attachmentUploadBegin(
        "owner", randomUUID(), channelId, ["owner"], 29, 1, "e".repeat(64),
      )).toEqual({ ok: true, data: { receivedChunks: [] } });
    } finally {
      store.close();
    }
  });

  it("rejects malformed, oversized, conflicting and incomplete chunks while allowing idempotent retries", () => {
    const { service, store } = serviceFixture();
    try {
      const state = service.getState("owner");
      if (!state.ok) throw new Error(state.error.message);
      const channelId = (state.data.channels as { id: string }[])[0]!.id;
      const ciphertext = Buffer.alloc(30 * 1024 + 17, 9);
      const chunks = encodeAttachmentChunks(ciphertext);
      const assetId = randomUUID();
      expect(service.attachmentUploadBegin(
        "owner", assetId, channelId, ["owner"], ciphertext.length, chunks.length, attachmentSha256(ciphertext),
      ).ok).toBe(true);

      expect(service.attachmentUploadChunk("owner", assetId, chunks[1]!.index, chunks[1]!.data, chunks[1]!.sizeBytes, chunks[1]!.hash).ok).toBe(true);
      expect(service.attachmentUploadComplete("owner", assetId)).toMatchObject({ ok: false, error: { code: "conflict" } });
      expect(service.attachmentUploadChunk("owner", assetId, chunks[1]!.index, chunks[1]!.data, chunks[1]!.sizeBytes, chunks[1]!.hash).ok).toBe(true);
      expect(service.attachmentUploadChunk("owner", assetId, chunks[1]!.index, Buffer.alloc(17, 8).toString("base64"), 17, attachmentSha256(Buffer.alloc(17, 8))))
        .toMatchObject({ ok: false, error: { code: "conflict" } });
      expect(service.attachmentUploadChunk("owner", assetId, chunks[0]!.index, `${chunks[0]!.data}=`, chunks[0]!.sizeBytes, chunks[0]!.hash))
        .toMatchObject({ ok: false, error: { code: "invalid_input" } });
      expect(service.attachmentUploadChunk("owner", assetId, chunks[0]!.index, chunks[0]!.data, chunks[0]!.sizeBytes, chunks[0]!.hash).ok).toBe(true);
      expect(service.attachmentUploadComplete("owner", assetId)).toEqual({ ok: true, data: null });

      const secondId = randomUUID();
      const config = service.getConfig();
      store.raw.prepare("UPDATE server_meta SET value = ? WHERE key = 'config'")
        .run(JSON.stringify({ ...config, maxSpoolBytes: ciphertext.length + 100 }));
      expect(service.attachmentUploadBegin("owner", secondId, channelId, ["owner"], 128, 1, "a".repeat(64)))
        .toMatchObject({ ok: false, error: { code: "rate_limited" } });
    } finally {
      store.close();
    }
  });

  it("binds attachment download to a linked envelope and rolls back mismatched audience atomically", () => {
    const { service, store } = serviceFixture();
    try {
      const invite = service.inviteCreate("owner", "role-member", 1);
      if (!invite.ok) throw new Error(invite.error.message);
      const memberKey = ed25519PublicKey(Buffer.alloc(32, 81)).toString("base64url");
      const joined = service.joinByInvite("member", "Member", invite.data.inviteKey, memberKey);
      if (!joined.ok) throw new Error(joined.error.message);
      const state = service.getState("owner");
      if (!state.ok) throw new Error(state.error.message);
      const channelId = (state.data.channels as { id: string }[])[0]!.id;
      const assetId = randomUUID();
      const ciphertext = Buffer.alloc(60, 9);
      const uploaded = uploadAttachment(service, { assetId, channelId, ciphertext });
      expect(uploaded.result.ok).toBe(true);
      expect(service.attachmentDownload("owner", assetId)).toMatchObject({ ok: false, error: { code: "forbidden" } });

      const envelope = buildEnvelope({
        serverId: service.getServerId(), channelId, sender: "owner", cryptoEpoch: 0,
        audience: { algo: "sha256", commitment: "", members: ["owner", "member"] },
        ciphertext: "AA==", ordering: { seq: 1 },
        attachments: [{ assetId, name: "secret.bin", mimeType: "application/octet-stream", sizeBytes: 32, totalChunks: uploaded.chunks.length, hash: "00".repeat(32) }],
      });
      expect(service.sendEnvelope("owner", envelope)).toMatchObject({ ok: false, error: { code: "conflict" } });
      expect(store.raw.prepare("SELECT count(*) AS count FROM spool WHERE message_id = ?").get(envelope.messageId)).toEqual({ count: 0 });
      expect(store.raw.prepare("SELECT linked_message_id FROM attachments WHERE asset_id = ?").get(assetId)).toEqual({ linked_message_id: null });
      const validEnvelope = buildEnvelope({
        serverId: service.getServerId(), channelId, sender: "owner", cryptoEpoch: 0,
        audience: { algo: "sha256", commitment: "", members: ["owner"] },
        ciphertext: "AA==", ordering: { seq: 2 }, attachments: envelope.attachments,
      });
      expect(service.sendEnvelope("owner", validEnvelope)).toEqual({ ok: true, data: null });
      expect(service.attachmentDownload("owner", assetId)).toEqual({
        ok: true,
        data: { sizeBytes: ciphertext.length, totalChunks: uploaded.chunks.length, hash: attachmentSha256(ciphertext) },
      });
      expect(service.attachmentDownloadChunk("owner", assetId, 0)).toMatchObject({
        ok: true,
        data: { index: 0, sizeBytes: ciphertext.length, hash: uploaded.chunks[0]!.hash },
      });
      expect(service.attachmentDownload("member", assetId)).toMatchObject({ ok: false, error: { code: "forbidden" } });
      expect(service.ackConsumed("member", validEnvelope.messageId)).toMatchObject({ ok: false, error: { code: "forbidden" } });
      expect(service.ackConsumed("owner", validEnvelope.messageId)).toEqual({ ok: true, data: null });
      expect(service.attachmentDownload("owner", assetId)).toMatchObject({ ok: false, error: { code: "not_found" } });
      expect(store.raw.prepare("SELECT count(*) AS count FROM attachment_chunks WHERE asset_id = ?").get(assetId)).toEqual({ count: 0 });
    } finally {
      store.close();
    }
  });
});
