import { describe, expect, it } from "vitest";
import {
  BridgeDescriptorPayloadSchema,
  BridgeRegistrationProofPayloadSchema,
  DirectRouteHintPayloadSchema,
  DirectRouteHintsConfigSchema,
  HostAuthChallengePayloadSchema,
  HostCommandSchema,
  HostGrantPayloadSchema,
  HostGrantRevocationPayloadSchema,
  HostRecordPayloadSchema,
  HostRegistrationSchema,
  InviteV3PayloadSchema,
  InviteV4PayloadSchema,
  SignedIceAccessProofSchema,
  PermissionFlagSchema,
  SignedBridgeDescriptorSchema,
  SignedBridgeRegistrationProofSchema,
  SignedDirectRouteHintSchema,
  SignedHostGrantRevocationSchema,
  SignedHostGrantSchema,
  SignedHostAuthChallengeSchema,
  SignedHostRecordSchema,
  SignedInviteV3Schema,
  SignedInviteV4Schema,
} from "./index.js";

const SERVER_ID = "11111111-1111-4111-8111-111111111111";
const GRANT_ID = "22222222-2222-4222-8222-222222222222";
const PUBLIC_KEY = "A".repeat(43);
const SIGNATURE = "B".repeat(86);

const bridgePayload = {
  version: 1,
  bridgeId: "bridge.example.test",
  endpoints: ["wss://bridge.example.test/connect"],
  issuedAt: 1_000,
  expiresAt: 2_000,
} as const;

const signedBridge = {
  payload: bridgePayload,
  publicKey: PUBLIC_KEY,
  signature: SIGNATURE,
};

const directRoutePayload = {
  version: 1,
  provider: "tailscale",
  routeId: "route-primary",
  endpoint: "wss://host.example.test/signal",
  serverId: SERVER_ID,
  hostId: "primary-host",
  hostPublicKey: PUBLIC_KEY,
  stable: true,
  issuedAt: 1_000,
  expiresAt: 2_000,
} as const;

const signedDirectRoute = {
  payload: directRoutePayload,
  publicKey: PUBLIC_KEY,
  signature: SIGNATURE,
};

describe("ICE access proof schema", () => {
  it("requires a session-bound signed device proof and an optional invite capability hash", () => {
    expect(SignedIceAccessProofSchema.safeParse({
      payload: {
        version: 1,
        sessionId: "S".repeat(32),
        serverId: SERVER_ID,
        hostId: "host-a",
        identityId: "member-a",
        devicePublicKey: PUBLIC_KEY,
        inviteAccessHash: "ab".repeat(32),
        issuedAt: 1_000,
        expiresAt: 2_000,
      },
      signature: SIGNATURE,
    }).success).toBe(true);
  });
});

describe("connectivity schemas", () => {
  it("accepts valid descriptors, JC3 invites, grants, revocations, and host records", () => {
    expect(BridgeDescriptorPayloadSchema.parse(bridgePayload)).toEqual(bridgePayload);
    expect(SignedBridgeDescriptorSchema.parse(signedBridge)).toEqual(signedBridge);

    const invite = {
      version: 3,
      serverId: SERVER_ID,
      authorityFingerprint: "ab".repeat(32),
      inviteSecret: "A".repeat(22),
      bridgeHints: [signedBridge],
      issuedAt: 1_000,
      expiresAt: 3_000,
    } as const;
    expect(InviteV3PayloadSchema.parse(invite)).toEqual(invite);
    expect(SignedInviteV3Schema.parse({ payload: invite, publicKey: PUBLIC_KEY, signature: SIGNATURE }).payload.serverId).toBe(SERVER_ID);

    const grant = {
      version: 1,
      grantId: GRANT_ID,
      serverId: SERVER_ID,
      issuerIdentityId: "owner",
      subjectIdentityId: "alice",
      subjectAuthPublicKey: PUBLIC_KEY,
      devicePublicKey: PUBLIC_KEY,
      hostId: "alice-desktop",
      capabilities: ["register", "replicate", "promote"],
      generation: 1,
      issuedAt: 1_000,
      expiresAt: 4_000,
    } as const;
    expect(HostGrantPayloadSchema.parse(grant)).toEqual(grant);
    expect(SignedHostGrantSchema.parse({ payload: grant, publicKey: PUBLIC_KEY, signature: SIGNATURE }).payload.hostId).toBe("alice-desktop");

    const revocation = {
      version: 1,
      serverId: SERVER_ID,
      grantId: GRANT_ID,
      hostId: "alice-desktop",
      issuerIdentityId: "owner",
      revokedAt: 2_000,
      generation: 2,
      reason: "device retired",
    } as const;
    expect(HostGrantRevocationPayloadSchema.parse(revocation)).toEqual(revocation);
    expect(SignedHostGrantRevocationSchema.parse({ payload: revocation, publicKey: PUBLIC_KEY, signature: SIGNATURE }).payload.grantId).toBe(GRANT_ID);

    const record = {
      version: 1,
      serverId: SERVER_ID,
      grantId: GRANT_ID,
      hostId: "alice-desktop",
      role: "replica",
      epoch: 7,
      recordSeq: 1,
      previousRecordHash: null,
      endpoints: ["wss://host.example.test/signal"],
      candidates: ["candidate:1 1 UDP 2122260223 192.0.2.1 5000 typ host"],
      issuedAt: 2_000,
      ttlMs: 60_000,
      expiresAt: 62_000,
    } as const;
    expect(HostRecordPayloadSchema.parse(record)).toEqual(record);
    expect(SignedHostRecordSchema.parse({ payload: record, publicKey: PUBLIC_KEY, signature: SIGNATURE }).payload.epoch).toBe(7);
    const registration = {
      authorityPublicKey: PUBLIC_KEY,
      grant: { payload: grant, publicKey: PUBLIC_KEY, signature: SIGNATURE },
      record: { payload: record, publicKey: PUBLIC_KEY, signature: SIGNATURE },
    };
    expect(HostRegistrationSchema.parse(registration).record.payload.hostId).toBe("alice-desktop");

    const hostChallenge = {
      version: 1,
      serverId: SERVER_ID,
      authorityFingerprint: "ab".repeat(32),
      hostId: "alice-desktop",
      grantId: GRANT_ID,
      challengeId: "33333333-3333-4333-8333-333333333333",
      nonce: "C".repeat(43),
      issuedAt: 2_000,
      expiresAt: 3_000,
    } as const;
    expect(HostAuthChallengePayloadSchema.parse(hostChallenge)).toEqual(hostChallenge);
    expect(SignedHostAuthChallengeSchema.parse({ payload: hostChallenge, publicKey: PUBLIC_KEY, signature: SIGNATURE }).payload.grantId).toBe(GRANT_ID);

    const registrationProof = {
      version: 1,
      serverId: SERVER_ID,
      hostId: "alice-desktop",
      grantId: GRANT_ID,
      recordHash: "ab".repeat(32),
      challengeId: "33333333-3333-4333-8333-333333333333",
      nonce: "D".repeat(43),
      issuedAt: 2_000,
      expiresAt: 3_000,
    } as const;
    expect(BridgeRegistrationProofPayloadSchema.parse(registrationProof)).toEqual(registrationProof);
    expect(SignedBridgeRegistrationProofSchema.parse({ payload: registrationProof, publicKey: PUBLIC_KEY, signature: SIGNATURE }).payload.recordHash).toBe("ab".repeat(32));
  });

  it("accepts strict direct-route config and a host-key-bound JC4 invite", () => {
    expect(DirectRouteHintsConfigSchema.parse([{
      provider: "ngrok",
      endpoint: "wss://route.example.test/signal",
      stable: false,
      expiresAt: 3_000,
    }])).toHaveLength(1);
    expect(DirectRouteHintPayloadSchema.parse(directRoutePayload)).toEqual(directRoutePayload);
    expect(SignedDirectRouteHintSchema.parse(signedDirectRoute)).toEqual(signedDirectRoute);

    const invite = {
      version: 4,
      serverId: SERVER_ID,
      authorityFingerprint: "ab".repeat(32),
      inviteSecret: "A".repeat(22),
      directRouteHints: [signedDirectRoute],
      bridgeHints: [signedBridge],
      issuedAt: 1_000,
      expiresAt: 3_000,
    } as const;
    expect(InviteV4PayloadSchema.parse(invite)).toEqual(invite);
    expect(SignedInviteV4Schema.parse({ payload: invite, publicKey: PUBLIC_KEY, signature: SIGNATURE }))
      .toMatchObject({ payload: { serverId: SERVER_ID } });
  });

  it("rejects unsafe, oversized, duplicate, cross-server, and authority-mismatched direct routes", () => {
    expect(DirectRouteHintsConfigSchema.safeParse([{
      provider: "manual",
      endpoint: "ws://host.example.test/signal",
      stable: true,
      expiresAt: 3_000,
    }]).success).toBe(false);
    expect(DirectRouteHintsConfigSchema.safeParse([{
      provider: "unknown",
      endpoint: "wss://host.example.test/signal",
      stable: true,
      expiresAt: 3_000,
    }]).success).toBe(false);
    expect(DirectRouteHintsConfigSchema.safeParse([{
      provider: "manual",
      endpoint: "wss://host.example.test/signal",
      stable: true,
      expiresAt: 3_000,
      token: "must-not-pass",
    }]).success).toBe(false);
    // contrato do env JC_DIRECT_ROUTE_HINTS: expiresAt obrigatório e sem startedAt
    expect(DirectRouteHintsConfigSchema.safeParse([{
      provider: "manual",
      endpoint: "wss://host.example.test/signal",
      stable: true,
    }]).success).toBe(false);
    expect(DirectRouteHintsConfigSchema.safeParse([{
      provider: "manual",
      endpoint: "wss://host.example.test/signal",
      stable: true,
      expiresAt: 3_000,
      startedAt: 1_000,
    }]).success).toBe(false);
    expect(DirectRouteHintsConfigSchema.safeParse([{
      provider: "manual",
      endpoint: "wss://host.example.test/signal?token=leak",
      stable: true,
      expiresAt: 3_000,
    }]).success).toBe(false);
    expect(DirectRouteHintsConfigSchema.safeParse(Array.from({ length: 4 }, (_, index) => ({
      provider: "manual",
      endpoint: `wss://host-${index}.example.test/signal`,
      stable: true,
      expiresAt: 3_000,
    }))).success).toBe(false);

    const invite = {
      version: 4,
      serverId: SERVER_ID,
      authorityFingerprint: "ab".repeat(32),
      inviteSecret: "A".repeat(22),
      directRouteHints: [signedDirectRoute],
      bridgeHints: [],
      issuedAt: 1_000,
      expiresAt: 3_000,
    } as const;
    expect(InviteV4PayloadSchema.safeParse({
      ...invite,
      directRouteHints: [{
        ...signedDirectRoute,
        payload: { ...directRoutePayload, serverId: "22222222-2222-4222-8222-222222222222" },
      }],
    }).success).toBe(false);
    expect(SignedInviteV4Schema.safeParse({
      payload: invite,
      publicKey: "C".repeat(43),
      signature: SIGNATURE,
    }).success).toBe(false);
  });

  it("rejects an invite with more than three bridge hints", () => {
    const result = InviteV3PayloadSchema.safeParse({
      version: 3,
      serverId: SERVER_ID,
      authorityFingerprint: "ab".repeat(32),
      inviteSecret: "A".repeat(22),
      bridgeHints: [signedBridge, signedBridge, signedBridge, signedBridge],
      issuedAt: 1_000,
      expiresAt: 3_000,
    });
    expect(result.success).toBe(false);
  });

  it("rejects malformed base64url keys", () => {
    expect(SignedBridgeDescriptorSchema.safeParse({ ...signedBridge, publicKey: "not/base64url=" }).success).toBe(false);
    expect(SignedBridgeDescriptorSchema.safeParse({ ...signedBridge, publicKey: "bad-key" }).success).toBe(false);
  });

  it("rejects invalid host records", () => {
    expect(HostRecordPayloadSchema.safeParse({
      version: 1,
      serverId: SERVER_ID,
      grantId: GRANT_ID,
      hostId: "alice-desktop",
      role: "leader",
      epoch: -1,
      recordSeq: 0,
      previousRecordHash: null,
      endpoints: [],
      candidates: [],
      issuedAt: 2_000,
      ttlMs: 0,
      expiresAt: 1_000,
    }).success).toBe(false);
  });

  it("accepts host grant commands and the expanded invite size", () => {
    expect(PermissionFlagSchema.parse("manage_hosts")).toBe("manage_hosts");
    expect(HostCommandSchema.safeParse({
      type: "role.create",
      name: "Host manager",
      level: 70,
      permissions: ["manage_hosts"],
    }).success).toBe(true);
    expect(HostCommandSchema.safeParse({
      type: "host.candidate.register",
      hostPublicKey: PUBLIC_KEY,
      enrollmentPublicKey: PUBLIC_KEY,
      hostId: "alice-desktop",
      deviceProof: { proofId: GRANT_ID, issuedAt: 1_000, signature: SIGNATURE },
      hostProof: { proofId: GRANT_ID, issuedAt: 1_000, signature: SIGNATURE },
    }).success).toBe(true);
    expect(HostCommandSchema.safeParse({
      type: "host.grant.create",
      subjectIdentityId: "alice",
      candidateId: GRANT_ID,
      capabilities: ["register", "replicate"],
      expiresInMs: 86_400_000,
    }).success).toBe(true);
    expect(HostCommandSchema.safeParse({ type: "host.grant.revoke", grantId: GRANT_ID }).success).toBe(true);
    const hostProof = { proofId: GRANT_ID, issuedAt: 1_000, signature: SIGNATURE };
    expect(HostCommandSchema.safeParse({ type: "host.grant.accept", grantId: GRANT_ID, hostProof }).success).toBe(true);
    expect(HostCommandSchema.safeParse({ type: "host.grant.list" }).success).toBe(true);
    expect(HostCommandSchema.safeParse({ type: "device.link.authorize", newDevicePublicKey: PUBLIC_KEY }).success).toBe(true);
    expect(HostCommandSchema.safeParse({ type: "device.enroll", capability: `JDL1-${"a".repeat(43)}` }).success).toBe(true);
    expect(HostCommandSchema.safeParse({ type: "device.enroll", inviteKey: "J".repeat(128) }).success).toBe(false);
    expect(HostCommandSchema.safeParse({ type: "invite.list" }).success).toBe(true);
    expect(HostCommandSchema.safeParse({ type: "replica.enroll", grantId: GRANT_ID, hostProof }).success).toBe(true);
    expect(HostCommandSchema.safeParse({ type: "replica.snapshot", grantId: GRANT_ID, serverId: SERVER_ID }).success).toBe(true);
    expect(HostCommandSchema.safeParse({ type: "replica.promote", grantId: GRANT_ID, expectedEpoch: 4 }).success).toBe(false);
    expect(HostCommandSchema.safeParse({ type: "replica.ping", grantId: GRANT_ID, serverId: SERVER_ID, epoch: 4 }).success).toBe(true);
    expect(HostCommandSchema.safeParse({ type: "replica.ping" }).success).toBe(false);
    expect(HostCommandSchema.safeParse({ type: "server.join", inviteKey: "J".repeat(2048) }).success).toBe(true);
    expect(HostCommandSchema.safeParse({ type: "server.join", inviteKey: "J", nickname: "Membro" }).success).toBe(true);
    expect(HostCommandSchema.safeParse({ type: "server.join", inviteKey: "J", nickname: "   " }).success).toBe(false);
    expect(HostCommandSchema.safeParse({ type: "server.join", inviteKey: "J", nickname: "N".repeat(65) }).success).toBe(false);
    expect(HostCommandSchema.safeParse({ type: "server.join", inviteKey: "J".repeat(2049) }).success).toBe(false);
  });

  it("accepts zrok as a direct route provider with a stable persistent route", () => {
    const zrokRoute = {
      ...directRoutePayload,
      provider: "zrok",
      endpoint: "wss://meu-servidor.shares.zrok.io/signal",
      stable: true,
    } as const;
    expect(DirectRouteHintPayloadSchema.parse(zrokRoute)).toEqual(zrokRoute);
    expect(DirectRouteHintPayloadSchema.safeParse({ ...zrokRoute, provider: "wireguard" }).success).toBe(false);
    expect(DirectRouteHintsConfigSchema.safeParse([{ provider: "zrok", endpoint: "wss://meu-servidor.shares.zrok.io/signal", stable: true, expiresAt: 2_000 }]).success).toBe(true);
  });
});
