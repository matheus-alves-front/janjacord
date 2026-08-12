import { describe, expect, it } from "vitest";
import { ed25519Fingerprint, ed25519PublicKey } from "@janjacord/crypto";
import {
  createSignedBridgeDescriptor,
  createSignedBridgeRegistrationProof,
  createSignedHostAuthChallenge,
  createSignedHostGrant,
  createSignedHostGrantRevocation,
  createSignedHostRecord,
  createSignedInviteV3,
  createSignedSessionAuth,
  formatInviteV3,
  hostRegistrationRecordHash,
  parseInviteV3,
  verifyHostRegistration,
  verifySignedBridgeRegistrationProof,
  verifySignedHostAuthChallenge,
  verifySignedHostGrantRevocation,
  verifySignedSessionAuth,
} from "./connectivity.js";

const SERVER_ID = "11111111-1111-4111-8111-111111111111";
const GRANT_ID = "22222222-2222-4222-8222-222222222222";
const authoritySeed = Buffer.alloc(32, 1);
const hostSeed = Buffer.alloc(32, 2);

describe("connectivity signatures", () => {
  it("roundtrips a verified JC3 and rejects tampering, expiry, and oversized values", () => {
    const now = 1_000;
    const bridgeSeed = Buffer.alloc(32, 3);
    const bridgeFingerprint = ed25519Fingerprint(ed25519PublicKey(bridgeSeed));
    const bridge = createSignedBridgeDescriptor({
      version: 1,
      bridgeId: `ed25519:${bridgeFingerprint}`,
      endpoints: ["wss://bridge.example/rendezvous"],
      issuedAt: now,
      expiresAt: now + 60_000,
    }, bridgeSeed);
    const invite = createSignedInviteV3({
      version: 3,
      serverId: SERVER_ID,
      authorityFingerprint: ed25519Fingerprint(ed25519PublicKey(authoritySeed)),
      inviteSecret: Buffer.alloc(16, 9).toString("base64url"),
      bridgeHints: [bridge],
      issuedAt: now,
      expiresAt: now + 30_000,
    }, authoritySeed);
    const key = formatInviteV3(invite);
    expect(parseInviteV3(key, now + 1)?.payload.serverId).toBe(SERVER_ID);
    expect(parseInviteV3(`${key.slice(0, -1)}A`, now + 1)).toBeNull();
    expect(parseInviteV3(key, now + 30_000)).toBeNull();
    expect(parseInviteV3(`JC3-${"A".repeat(2049)}`, now)).toBeNull();
  });

  it("requires a valid, matching, unrevoked grant for a host record", () => {
    const now = 10_000;
    const authorityPublicKey = ed25519PublicKey(authoritySeed).toString("base64url");
    const devicePublicKey = ed25519PublicKey(hostSeed).toString("base64url");
    const grant = createSignedHostGrant({
      version: 1,
      grantId: GRANT_ID,
      serverId: SERVER_ID,
      issuerIdentityId: "owner",
      subjectIdentityId: "member",
      subjectAuthPublicKey: devicePublicKey,
      devicePublicKey,
      hostId: "member-device",
      capabilities: ["register", "replicate", "promote"],
      generation: 1,
      issuedAt: now,
      expiresAt: now + 120_000,
    }, authoritySeed);
    const record = createSignedHostRecord({
      version: 1,
      serverId: SERVER_ID,
      grantId: GRANT_ID,
      hostId: "member-device",
      role: "replica",
      epoch: 4,
      recordSeq: 1,
      previousRecordHash: null,
      endpoints: ["wss://host.example/signal"],
      candidates: [],
      issuedAt: now,
      ttlMs: 60_000,
      expiresAt: now + 60_000,
    }, hostSeed);

    expect(verifyHostRegistration({ record, grant, authorityPublicKey, now: now + 1 })).not.toBeNull();
    expect(verifyHostRegistration({ record, grant, authorityPublicKey, revokedGrantIds: new Set([GRANT_ID]), now: now + 1 })).toBeNull();
    expect(verifyHostRegistration({ record: { ...record, payload: { ...record.payload, epoch: 99 } }, grant, authorityPublicKey, now: now + 1 })).toBeNull();

    const revocation = createSignedHostGrantRevocation({
      version: 1,
      serverId: SERVER_ID,
      grantId: GRANT_ID,
      hostId: "member-device",
      issuerIdentityId: "owner",
      revokedAt: now + 2,
      generation: 2,
    }, authoritySeed);
    expect(verifySignedHostGrantRevocation(revocation, authorityPublicKey)?.payload.grantId).toBe(GRANT_ID);
  });

  it("binds session proof to server, challenge, nonce, identity, and device key", () => {
    const now = 50_000;
    const challengeId = "33333333-3333-4333-8333-333333333333";
    const proof = createSignedSessionAuth({
      version: 1,
      serverId: SERVER_ID,
      identityId: "member",
      publicKey: ed25519PublicKey(hostSeed).toString("base64url"),
      challengeId,
      nonce: Buffer.alloc(32, 8).toString("base64url"),
      issuedAt: now,
      expiresAt: now + 30_000,
    }, hostSeed);
    const expected = { serverId: SERVER_ID, challengeId, nonce: proof.payload.nonce };
    expect(verifySignedSessionAuth(proof, expected, now + 1)?.payload.identityId).toBe("member");
    expect(verifySignedSessionAuth(proof, { ...expected, nonce: "wrong" }, now + 1)).toBeNull();
    expect(verifySignedSessionAuth(proof, expected, now + 30_000)).toBeNull();
  });

  it("binds a host challenge to the resolved host key, grant, and record identity", () => {
    const now = 70_000;
    const challenge = createSignedHostAuthChallenge({
      version: 1,
      serverId: SERVER_ID,
      authorityFingerprint: ed25519Fingerprint(ed25519PublicKey(authoritySeed)),
      hostId: "member-device",
      grantId: GRANT_ID,
      challengeId: "33333333-3333-4333-8333-333333333333",
      nonce: Buffer.alloc(32, 7).toString("base64url"),
      issuedAt: now,
      expiresAt: now + 30_000,
    }, hostSeed);
    const expected = {
      serverId: SERVER_ID,
      authorityFingerprint: ed25519Fingerprint(ed25519PublicKey(authoritySeed)),
      hostPublicKey: ed25519PublicKey(hostSeed).toString("base64url"),
      hostId: "member-device",
      grantId: GRANT_ID,
    };
    expect(verifySignedHostAuthChallenge(challenge, expected, now + 1)).not.toBeNull();
    expect(verifySignedHostAuthChallenge(challenge, { ...expected, grantId: "44444444-4444-4444-8444-444444444444" }, now + 1)).toBeNull();
    expect(verifySignedHostAuthChallenge(challenge, { ...expected, hostPublicKey: ed25519PublicKey(authoritySeed).toString("base64url") }, now + 1)).toBeNull();
  });

  it("proves live bridge registration with the host key and exact pending record hash", () => {
    const now = 90_000;
    const record = createSignedHostRecord({
      version: 1,
      serverId: SERVER_ID,
      grantId: GRANT_ID,
      hostId: "member-device",
      role: "replica",
      epoch: 2,
      recordSeq: 4,
      previousRecordHash: null,
      endpoints: ["wss://host.example/signal"],
      candidates: [],
      issuedAt: now,
      ttlMs: 60_000,
      expiresAt: now + 60_000,
    }, hostSeed);
    const recordHash = hostRegistrationRecordHash(record);
    const challengeId = "55555555-5555-4555-8555-555555555555";
    const nonce = Buffer.alloc(32, 6).toString("base64url");
    const proof = createSignedBridgeRegistrationProof({
      version: 1,
      serverId: SERVER_ID,
      hostId: "member-device",
      grantId: GRANT_ID,
      recordHash,
      challengeId,
      nonce,
      issuedAt: now,
      expiresAt: now + 30_000,
    }, hostSeed);
    const expected = {
      hostPublicKey: ed25519PublicKey(hostSeed).toString("base64url"),
      serverId: SERVER_ID,
      hostId: "member-device",
      grantId: GRANT_ID,
      recordHash,
      challengeId,
      nonce,
    };
    expect(verifySignedBridgeRegistrationProof(proof, expected, now + 1)).not.toBeNull();
    expect(verifySignedBridgeRegistrationProof(proof, { ...expected, recordHash: "00".repeat(32) }, now + 1)).toBeNull();
    expect(verifySignedBridgeRegistrationProof(proof, expected, now + 30_000)).toBeNull();
  });
});
