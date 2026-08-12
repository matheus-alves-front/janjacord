import { describe, expect, it } from "vitest";
import { ed25519Fingerprint, ed25519PublicKey } from "@janjacord/crypto";
import { createSignedHostGrant, createSignedHostRecord } from "@janjacord/protocol";
import { verifyHostAuthenticationContext } from "./connectivity.js";

const SERVER_ID = "11111111-1111-4111-8111-111111111111";
const GRANT_ID = "22222222-2222-4222-8222-222222222222";

function registration(now: number) {
  const authoritySeed = Buffer.alloc(32, 11);
  const hostSeed = Buffer.alloc(32, 12);
  const authorityPublicKey = ed25519PublicKey(authoritySeed).toString("base64url");
  const hostPublicKey = ed25519PublicKey(hostSeed).toString("base64url");
  const grant = createSignedHostGrant({
    version: 1,
    grantId: GRANT_ID,
    serverId: SERVER_ID,
    issuerIdentityId: "owner",
    subjectIdentityId: "owner",
    subjectAuthPublicKey: ed25519PublicKey(Buffer.alloc(32, 13)).toString("base64url"),
    devicePublicKey: hostPublicKey,
    hostId: "primary-host",
    capabilities: ["register", "replicate", "promote"],
    generation: 1,
    issuedAt: now,
    expiresAt: now + 120_000,
  }, authoritySeed);
  const record = createSignedHostRecord({
    version: 1,
    serverId: SERVER_ID,
    grantId: GRANT_ID,
    hostId: "primary-host",
    role: "primary",
    epoch: 1,
    recordSeq: 1,
    previousRecordHash: null,
    endpoints: ["wss://host.example/signal"],
    candidates: [],
    issuedAt: now,
    ttlMs: 60_000,
    expiresAt: now + 60_000,
  }, hostSeed);
  return {
    chain: { authorityPublicKey, grant, record },
    authorityFingerprint: ed25519Fingerprint(Buffer.from(authorityPublicKey, "base64url")),
  };
}

describe("host authentication context", () => {
  it("accepts a matching authority/grant/record chain", () => {
    const now = 10_000;
    const input = registration(now);
    expect(verifyHostAuthenticationContext(input.chain, {
      serverId: SERVER_ID,
      authorityFingerprint: input.authorityFingerprint,
      hostId: "primary-host",
      now: now + 1,
    })).toMatchObject({ grantId: GRANT_ID, hostId: "primary-host" });
  });

  it("rejects authority substitution, record tampering, and host mismatch", () => {
    const now = 20_000;
    const input = registration(now);
    expect(verifyHostAuthenticationContext(input.chain, {
      serverId: SERVER_ID,
      authorityFingerprint: "00".repeat(32),
      now: now + 1,
    })).toBeNull();
    expect(verifyHostAuthenticationContext({
      ...input.chain,
      record: { ...input.chain.record, payload: { ...input.chain.record.payload, epoch: 99 } },
    }, {
      serverId: SERVER_ID,
      authorityFingerprint: input.authorityFingerprint,
      now: now + 1,
    })).toBeNull();
    expect(verifyHostAuthenticationContext(input.chain, {
      serverId: SERVER_ID,
      authorityFingerprint: input.authorityFingerprint,
      hostId: "other-host",
      now: now + 1,
    })).toBeNull();
  });
});
