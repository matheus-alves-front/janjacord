import {
  BridgeDescriptorPayloadSchema,
  BridgeWitnessPayloadSchema,
  BridgeRegistrationProofPayloadSchema,
  DirectRouteHintPayloadSchema,
  HostGrantPayloadSchema,
  HostAuthChallengePayloadSchema,
  HostGrantRevocationPayloadSchema,
  HostRecordPayloadSchema,
  InviteV3PayloadSchema,
  InviteV4PayloadSchema,
  SignedBridgeDescriptorSchema,
  SignedBridgeWitnessSchema,
  SignedBridgeRegistrationProofSchema,
  SignedDirectRouteHintSchema,
  SignedHostGrantRevocationSchema,
  SignedHostGrantSchema,
  SignedHostAuthChallengeSchema,
  SignedHostRecordSchema,
  SignedInviteV3Schema,
  SignedInviteV4Schema,
  SignedSessionAuthSchema,
  type BridgeDescriptorPayload,
  type BridgeWitnessPayload,
  type BridgeRegistrationProofPayload,
  type DirectRouteHintPayload,
  type HostGrantPayload,
  type HostAuthChallengePayload,
  type HostGrantRevocationPayload,
  type HostRecordPayload,
  type InviteV3Payload,
  type InviteV4Payload,
  type SignedBridgeDescriptor,
  type SignedBridgeWitness,
  type SignedBridgeRegistrationProof,
  type SignedDirectRouteHint,
  type SignedHostGrant,
  type SignedHostAuthChallenge,
  type SignedHostGrantRevocation,
  type SignedHostRecord,
  type SignedInviteV3,
  type SignedInviteV4,
  type SessionAuthPayload,
  type SignedSessionAuth,
} from "@janjacord/schemas";
import {
  canonicalJson,
  ed25519Fingerprint,
  ed25519PublicKey,
  sha256Hex,
  signCanonicalPayload,
  verifyCanonicalPayload,
} from "@janjacord/crypto";

export const SIGNATURE_DOMAINS = {
  bridgeDescriptor: "janjacord.bridge-descriptor.v1",
  bridgeWitness: "janjacord.bridge-witness.v1",
  directRouteHint: "janjacord.direct-route-hint.v1",
  inviteV3: "janjacord.invite.v3",
  inviteV4: "janjacord.invite.v4",
  hostGrant: "janjacord.host-grant.v1",
  hostGrantRevocation: "janjacord.host-grant-revocation.v1",
  hostRecord: "janjacord.host-record.v1",
  sessionAuth: "janjacord.session-auth.v1",
  hostAuthChallenge: "janjacord.host-auth-challenge.v1",
  bridgeRegistrationProof: "janjacord.bridge-registration-proof.v1",
} as const;

export const MAX_INVITE_V3_CHARS = 2048;
export const MAX_INVITE_V4_CHARS = 2048;

function toBase64Url(data: Buffer): string {
  return data.toString("base64url");
}

function fromBase64Url(value: string): Buffer {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) throw new Error("invalid base64url");
  const decoded = Buffer.from(value, "base64url");
  if (decoded.toString("base64url") !== value) throw new Error("non-canonical base64url");
  return decoded;
}

function signPayload<T>(seed: Buffer, domain: string, payload: T): { payload: T; publicKey: string; signature: string } {
  const publicKey = ed25519PublicKey(seed);
  return {
    payload,
    publicKey: toBase64Url(publicKey),
    signature: toBase64Url(signCanonicalPayload(seed, domain, payload)),
  };
}

function verifySigned(domain: string, value: { payload: unknown; publicKey: string; signature: string }): boolean {
  try {
    return verifyCanonicalPayload(
      fromBase64Url(value.publicKey),
      domain,
      value.payload,
      fromBase64Url(value.signature),
    );
  } catch {
    return false;
  }
}

export function createSignedBridgeDescriptor(payload: BridgeDescriptorPayload, seed: Buffer): SignedBridgeDescriptor {
  return SignedBridgeDescriptorSchema.parse(signPayload(seed, SIGNATURE_DOMAINS.bridgeDescriptor, BridgeDescriptorPayloadSchema.parse(payload)));
}

export function verifySignedBridgeDescriptor(value: unknown, now = Date.now()): SignedBridgeDescriptor | null {
  const parsed = SignedBridgeDescriptorSchema.safeParse(value);
  if (!parsed.success || parsed.data.payload.expiresAt <= now) return null;
  try {
    const fingerprint = ed25519Fingerprint(fromBase64Url(parsed.data.publicKey));
    if (![fingerprint, `ed25519:${fingerprint}`].includes(parsed.data.payload.bridgeId)) return null;
  } catch {
    return null;
  }
  return verifySigned(SIGNATURE_DOMAINS.bridgeDescriptor, parsed.data) ? parsed.data : null;
}

export function createSignedBridgeWitness(payload: BridgeWitnessPayload, seed: Buffer): SignedBridgeWitness {
  return SignedBridgeWitnessSchema.parse(
    signPayload(seed, SIGNATURE_DOMAINS.bridgeWitness, BridgeWitnessPayloadSchema.parse(payload)),
  );
}

export function verifySignedBridgeWitness(
  value: unknown,
  descriptor: SignedBridgeDescriptor,
  now = Date.now(),
): SignedBridgeWitness | null {
  const parsed = SignedBridgeWitnessSchema.safeParse(value);
  if (!parsed.success || !verifySignedBridgeDescriptor(descriptor, now)) return null;
  if (parsed.data.publicKey !== descriptor.publicKey
    || parsed.data.payload.bridgeId !== descriptor.payload.bridgeId
    || parsed.data.payload.expiresAt <= now
    || parsed.data.payload.expiresAt > parsed.data.payload.observedAt + 10_000
    || Math.abs(now - parsed.data.payload.observedAt) > 10_000) return null;
  return verifySigned(SIGNATURE_DOMAINS.bridgeWitness, parsed.data) ? parsed.data : null;
}

export function createSignedDirectRouteHint(
  payload: DirectRouteHintPayload,
  authoritySeed: Buffer,
): SignedDirectRouteHint {
  return SignedDirectRouteHintSchema.parse(
    signPayload(
      authoritySeed,
      SIGNATURE_DOMAINS.directRouteHint,
      DirectRouteHintPayloadSchema.parse(payload),
    ),
  );
}

export function verifySignedDirectRouteHint(
  value: unknown,
  expected: {
    authorityPublicKey: string;
    serverId: string;
    hostId?: string;
    hostPublicKey?: string;
  },
  now = Date.now(),
): SignedDirectRouteHint | null {
  const parsed = SignedDirectRouteHintSchema.safeParse(value);
  if (!parsed.success
    || parsed.data.publicKey !== expected.authorityPublicKey
    || parsed.data.payload.serverId !== expected.serverId
    || parsed.data.payload.expiresAt <= now
    || parsed.data.payload.issuedAt > now + 5_000) return null;
  if (expected.hostId && parsed.data.payload.hostId !== expected.hostId) return null;
  if (expected.hostPublicKey && parsed.data.payload.hostPublicKey !== expected.hostPublicKey) return null;
  return verifySigned(SIGNATURE_DOMAINS.directRouteHint, parsed.data) ? parsed.data : null;
}

export function createSignedInviteV3(payload: InviteV3Payload, seed: Buffer): SignedInviteV3 {
  const parsed = InviteV3PayloadSchema.parse(payload);
  const publicKey = ed25519PublicKey(seed);
  if (ed25519Fingerprint(publicKey) !== parsed.authorityFingerprint.toLowerCase()) {
    throw new Error("invite authority fingerprint does not match signing key");
  }
  return SignedInviteV3Schema.parse(signPayload(seed, SIGNATURE_DOMAINS.inviteV3, parsed));
}

export function verifySignedInviteV3(value: unknown, now = Date.now()): SignedInviteV3 | null {
  const parsed = SignedInviteV3Schema.safeParse(value);
  if (!parsed.success || parsed.data.payload.expiresAt <= now) return null;
  try {
    const publicKey = fromBase64Url(parsed.data.publicKey);
    if (ed25519Fingerprint(publicKey) !== parsed.data.payload.authorityFingerprint.toLowerCase()) return null;
  } catch {
    return null;
  }
  if (parsed.data.payload.bridgeHints.some((descriptor) => !verifySignedBridgeDescriptor(descriptor, now))) return null;
  return verifySigned(SIGNATURE_DOMAINS.inviteV3, parsed.data) ? parsed.data : null;
}

export function formatInviteV3(invite: SignedInviteV3): string {
  const encoded = `JC3-${toBase64Url(Buffer.from(canonicalJson(SignedInviteV3Schema.parse(invite)), "utf8"))}`;
  if (encoded.length > MAX_INVITE_V3_CHARS) throw new Error(`JC3 exceeds ${MAX_INVITE_V3_CHARS} characters`);
  return encoded;
}

export function parseInviteV3(key: string, now = Date.now()): SignedInviteV3 | null {
  const value = key.trim();
  if (!value.startsWith("JC3-") || value.length > MAX_INVITE_V3_CHARS) return null;
  try {
    const raw = fromBase64Url(value.slice(4)).toString("utf8");
    return verifySignedInviteV3(JSON.parse(raw), now);
  } catch {
    return null;
  }
}

export function createSignedInviteV4(payload: InviteV4Payload, seed: Buffer): SignedInviteV4 {
  const parsed = InviteV4PayloadSchema.parse(payload);
  const publicKey = ed25519PublicKey(seed);
  if (ed25519Fingerprint(publicKey) !== parsed.authorityFingerprint.toLowerCase()) {
    throw new Error("invite authority fingerprint does not match signing key");
  }
  return SignedInviteV4Schema.parse(signPayload(seed, SIGNATURE_DOMAINS.inviteV4, parsed));
}

export function verifySignedInviteV4(value: unknown, now = Date.now()): SignedInviteV4 | null {
  const parsed = SignedInviteV4Schema.safeParse(value);
  if (!parsed.success || parsed.data.payload.expiresAt <= now || parsed.data.payload.issuedAt > now + 5_000) return null;
  try {
    const publicKey = fromBase64Url(parsed.data.publicKey);
    if (ed25519Fingerprint(publicKey) !== parsed.data.payload.authorityFingerprint.toLowerCase()) return null;
  } catch {
    return null;
  }
  const expectedRoute = {
    authorityPublicKey: parsed.data.publicKey,
    serverId: parsed.data.payload.serverId,
  };
  if (parsed.data.payload.directRouteHints.some((route) => !verifySignedDirectRouteHint(route, expectedRoute, now))) {
    return null;
  }
  if (parsed.data.payload.bridgeHints.some((descriptor) => !verifySignedBridgeDescriptor(descriptor, now))) return null;
  return verifySigned(SIGNATURE_DOMAINS.inviteV4, parsed.data) ? parsed.data : null;
}

export function formatInviteV4(invite: SignedInviteV4): string {
  const encoded = `JC4-${toBase64Url(Buffer.from(canonicalJson(SignedInviteV4Schema.parse(invite)), "utf8"))}`;
  if (encoded.length > MAX_INVITE_V4_CHARS) throw new Error(`JC4 exceeds ${MAX_INVITE_V4_CHARS} characters`);
  return encoded;
}

export function parseInviteV4(key: string, now = Date.now()): SignedInviteV4 | null {
  const value = key.trim();
  if (!value.startsWith("JC4-") || value.length > MAX_INVITE_V4_CHARS) return null;
  try {
    const raw = fromBase64Url(value.slice(4)).toString("utf8");
    return verifySignedInviteV4(JSON.parse(raw), now);
  } catch {
    return null;
  }
}

export function createSignedHostGrant(payload: HostGrantPayload, authoritySeed: Buffer): SignedHostGrant {
  return SignedHostGrantSchema.parse(signPayload(authoritySeed, SIGNATURE_DOMAINS.hostGrant, HostGrantPayloadSchema.parse(payload)));
}

export function verifySignedHostGrant(
  value: unknown,
  authorityPublicKey: string,
  now = Date.now(),
): SignedHostGrant | null {
  const parsed = SignedHostGrantSchema.safeParse(value);
  if (!parsed.success || parsed.data.publicKey !== authorityPublicKey || parsed.data.payload.expiresAt <= now) return null;
  return verifySigned(SIGNATURE_DOMAINS.hostGrant, parsed.data) ? parsed.data : null;
}

export function createSignedHostGrantRevocation(
  payload: HostGrantRevocationPayload,
  authoritySeed: Buffer,
): SignedHostGrantRevocation {
  return SignedHostGrantRevocationSchema.parse(
    signPayload(authoritySeed, SIGNATURE_DOMAINS.hostGrantRevocation, HostGrantRevocationPayloadSchema.parse(payload)),
  );
}

export function verifySignedHostGrantRevocation(
  value: unknown,
  authorityPublicKey: string,
): SignedHostGrantRevocation | null {
  const parsed = SignedHostGrantRevocationSchema.safeParse(value);
  if (!parsed.success || parsed.data.publicKey !== authorityPublicKey) return null;
  return verifySigned(SIGNATURE_DOMAINS.hostGrantRevocation, parsed.data) ? parsed.data : null;
}

export function createSignedHostRecord(payload: HostRecordPayload, deviceSeed: Buffer): SignedHostRecord {
  return SignedHostRecordSchema.parse(signPayload(deviceSeed, SIGNATURE_DOMAINS.hostRecord, HostRecordPayloadSchema.parse(payload)));
}

export function verifySignedHostRecord(value: unknown, devicePublicKey: string, now = Date.now()): SignedHostRecord | null {
  const parsed = SignedHostRecordSchema.safeParse(value);
  if (!parsed.success || parsed.data.publicKey !== devicePublicKey || parsed.data.payload.expiresAt <= now) return null;
  if (parsed.data.payload.expiresAt > parsed.data.payload.issuedAt + parsed.data.payload.ttlMs) return null;
  return verifySigned(SIGNATURE_DOMAINS.hostRecord, parsed.data) ? parsed.data : null;
}

export function verifyHostRegistration(input: {
  record: unknown;
  grant: unknown;
  authorityPublicKey: string;
  revokedGrantIds?: ReadonlySet<string>;
  now?: number;
}): { record: SignedHostRecord; grant: SignedHostGrant } | null {
  const now = input.now ?? Date.now();
  const grant = verifySignedHostGrant(input.grant, input.authorityPublicKey, now);
  if (!grant || input.revokedGrantIds?.has(grant.payload.grantId)) return null;
  if (!grant.payload.capabilities.includes("register")) return null;
  const record = verifySignedHostRecord(input.record, grant.payload.devicePublicKey, now);
  if (!record) return null;
  if (
    record.payload.serverId !== grant.payload.serverId ||
    record.payload.grantId !== grant.payload.grantId ||
    record.payload.hostId !== grant.payload.hostId
  ) return null;
  if (record.payload.role === "replica" && !grant.payload.capabilities.includes("replicate")) return null;
  if (record.payload.role === "primary" && !grant.payload.capabilities.includes("promote")) return null;
  return { record, grant };
}

/** Hash challenged by JanjaBridge. It covers the signed record, not only its mutable payload. */
export function hostRegistrationRecordHash(record: unknown): string {
  return sha256Hex(canonicalJson(SignedHostRecordSchema.parse(record)));
}

export function createSignedSessionAuth(payload: SessionAuthPayload, deviceSeed: Buffer): SignedSessionAuth {
  const signed = signPayload(deviceSeed, SIGNATURE_DOMAINS.sessionAuth, payload);
  if (signed.publicKey !== payload.publicKey) throw new Error("session public key does not match signing key");
  return SignedSessionAuthSchema.parse({ payload: signed.payload, signature: signed.signature });
}

export function verifySignedSessionAuth(value: unknown, expected: {
  serverId: string;
  challengeId: string;
  nonce: string;
}, now = Date.now()): SignedSessionAuth | null {
  const parsed = SignedSessionAuthSchema.safeParse(value);
  if (!parsed.success || parsed.data.payload.expiresAt <= now || parsed.data.payload.issuedAt > now + 5_000) return null;
  if (
    parsed.data.payload.serverId !== expected.serverId ||
    parsed.data.payload.challengeId !== expected.challengeId ||
    parsed.data.payload.nonce !== expected.nonce
  ) return null;
  const signed = { ...parsed.data, publicKey: parsed.data.payload.publicKey };
  return verifySigned(SIGNATURE_DOMAINS.sessionAuth, signed) ? parsed.data : null;
}

export function createSignedHostAuthChallenge(
  payload: HostAuthChallengePayload,
  hostSeed: Buffer,
): SignedHostAuthChallenge {
  const parsed = HostAuthChallengePayloadSchema.parse(payload);
  return SignedHostAuthChallengeSchema.parse(signPayload(hostSeed, SIGNATURE_DOMAINS.hostAuthChallenge, parsed));
}

export function verifySignedHostAuthChallenge(value: unknown, expected: {
  serverId?: string;
  authorityFingerprint?: string;
  hostPublicKey?: string;
  hostId?: string;
  grantId?: string;
}, now = Date.now()): SignedHostAuthChallenge | null {
  const parsed = SignedHostAuthChallengeSchema.safeParse(value);
  if (!parsed.success || parsed.data.payload.expiresAt <= now || parsed.data.payload.issuedAt > now + 5_000) return null;
  if (expected.serverId && parsed.data.payload.serverId !== expected.serverId) return null;
  if (expected.authorityFingerprint && parsed.data.payload.authorityFingerprint !== expected.authorityFingerprint.toLowerCase()) return null;
  if (expected.hostPublicKey && parsed.data.publicKey !== expected.hostPublicKey) return null;
  if (expected.hostId && parsed.data.payload.hostId !== expected.hostId) return null;
  if (expected.grantId && parsed.data.payload.grantId !== expected.grantId) return null;
  return verifySigned(SIGNATURE_DOMAINS.hostAuthChallenge, parsed.data) ? parsed.data : null;
}

/**
 * Pins the WSS peer challenge to the exact host identity carried by an already trusted JC4 route.
 * Pass the enclosing parsed JC4 invite's public key as the authority anchor.
 */
export function verifyDirectRouteHostAuthChallenge(
  value: unknown,
  route: SignedDirectRouteHint,
  expectedAuthorityPublicKey: string,
  now = Date.now(),
): SignedHostAuthChallenge | null {
  const parsedRoute = SignedDirectRouteHintSchema.safeParse(route);
  if (!parsedRoute.success || !verifySignedDirectRouteHint(parsedRoute.data, {
    authorityPublicKey: expectedAuthorityPublicKey,
    serverId: parsedRoute.data.payload.serverId,
  }, now)) return null;
  let authorityFingerprint: string;
  try {
    authorityFingerprint = ed25519Fingerprint(fromBase64Url(expectedAuthorityPublicKey));
  } catch {
    return null;
  }
  return verifySignedHostAuthChallenge(value, {
    serverId: parsedRoute.data.payload.serverId,
    authorityFingerprint,
    hostPublicKey: parsedRoute.data.payload.hostPublicKey,
    hostId: parsedRoute.data.payload.hostId,
  }, now);
}

export function createSignedBridgeRegistrationProof(
  payload: BridgeRegistrationProofPayload,
  hostSeed: Buffer,
): SignedBridgeRegistrationProof {
  return SignedBridgeRegistrationProofSchema.parse(
    signPayload(hostSeed, SIGNATURE_DOMAINS.bridgeRegistrationProof, BridgeRegistrationProofPayloadSchema.parse(payload)),
  );
}

export function verifySignedBridgeRegistrationProof(value: unknown, expected: {
  hostPublicKey: string;
  serverId: string;
  hostId: string;
  grantId: string;
  recordHash: string;
  challengeId: string;
  nonce: string;
}, now = Date.now()): SignedBridgeRegistrationProof | null {
  const parsed = SignedBridgeRegistrationProofSchema.safeParse(value);
  if (!parsed.success || parsed.data.payload.expiresAt <= now || parsed.data.payload.issuedAt > now + 5_000) return null;
  if (
    parsed.data.publicKey !== expected.hostPublicKey ||
    parsed.data.payload.serverId !== expected.serverId ||
    parsed.data.payload.hostId !== expected.hostId ||
    parsed.data.payload.grantId !== expected.grantId ||
    parsed.data.payload.recordHash !== expected.recordHash ||
    parsed.data.payload.challengeId !== expected.challengeId ||
    parsed.data.payload.nonce !== expected.nonce
  ) return null;
  return verifySigned(SIGNATURE_DOMAINS.bridgeRegistrationProof, parsed.data) ? parsed.data : null;
}
