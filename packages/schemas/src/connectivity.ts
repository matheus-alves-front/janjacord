import { z } from "zod";
import { uuidSchema } from "./envelope.js";

export const BRIDGE_DESCRIPTOR_VERSION = 1 as const;
export const INVITE_V3_VERSION = 3 as const;
export const HOST_GRANT_VERSION = 1 as const;
export const HOST_GRANT_REVOCATION_VERSION = 1 as const;
export const HOST_RECORD_VERSION = 1 as const;
export const SESSION_AUTH_VERSION = 1 as const;
export const ICE_ACCESS_PROOF_VERSION = 1 as const;
export const HOST_AUTH_CHALLENGE_VERSION = 1 as const;
export const BRIDGE_REGISTRATION_PROOF_VERSION = 1 as const;

export const MAX_BRIDGE_HINTS = 3;
export const MAX_CONNECTIVITY_ENDPOINTS = 8;
export const MAX_ICE_CANDIDATES = 32;

/** Unpadded RFC 4648 base64url text used by Ed25519 keys and signatures. */
export const Base64UrlSchema = z
  .string()
  .min(1)
  .regex(/^[A-Za-z0-9_-]+$/, "invalid base64url");

/** Raw 32-byte Ed25519 public key encoded as unpadded base64url. */
export const PublicKeySchema = z
  .string()
  .regex(/^[A-Za-z0-9_-]{43}$/, "expected base64url-encoded Ed25519 public key");

/** Raw 64-byte Ed25519 signature encoded as unpadded base64url. */
export const SignatureSchema = z
  .string()
  .regex(/^[A-Za-z0-9_-]{86}$/, "expected base64url-encoded Ed25519 signature");

export const AuthorityFingerprintSchema = z
  .string()
  .regex(/^[0-9a-fA-F]{64}$/, "expected 64-character hex fingerprint");
const Hex64Schema = z.string().regex(/^[0-9a-f]{64}$/, "expected lowercase sha256 hex");

const timestampSchema = z.number().int().nonnegative();
const identityIdSchema = z.string().min(1).max(128);
const hostIdSchema = z.string().min(1).max(128);
const endpointSchema = z.string().min(1).max(2048).superRefine((value, ctx) => {
  try {
    const url = new URL(value);
    if (!["wss:", "https:", "stun:", "stuns:", "turn:", "turns:"].includes(url.protocol)) {
      ctx.addIssue({ code: "custom", message: "connectivity endpoint must use TLS-capable protocol" });
    }
  } catch {
    ctx.addIssue({ code: "custom", message: "invalid connectivity endpoint URL" });
  }
});
const iceCandidateSchema = z.string().min(1).max(4096);

function expiresAfterIssue<T extends { issuedAt: number; expiresAt: number }>(value: T): boolean {
  return value.expiresAt > value.issuedAt;
}

export const BridgeDescriptorPayloadSchema = z
  .object({
    version: z.literal(BRIDGE_DESCRIPTOR_VERSION),
    bridgeId: z.string().min(1).max(128),
    endpoints: z.array(endpointSchema).min(1).max(MAX_CONNECTIVITY_ENDPOINTS),
    issuedAt: timestampSchema,
    expiresAt: timestampSchema,
  })
  .strict()
  .refine(expiresAfterIssue, {
    path: ["expiresAt"],
    message: "expiresAt must be greater than issuedAt",
  });

export type BridgeDescriptorPayload = z.infer<typeof BridgeDescriptorPayloadSchema>;

export const SignedBridgeDescriptorSchema = z
  .object({
    payload: BridgeDescriptorPayloadSchema,
    publicKey: PublicKeySchema,
    signature: SignatureSchema,
  })
  .strict();

export type SignedBridgeDescriptor = z.infer<typeof SignedBridgeDescriptorSchema>;

export const BridgeWitnessPayloadSchema = z.object({
  version: z.literal(1),
  bridgeId: z.string().regex(/^ed25519:[0-9a-f]{64}$/),
  requestId: z.string().uuid(),
  serverId: uuidSchema,
  replicaHostId: z.string().min(1).max(128),
  primaryHostId: z.string().min(1).max(128),
  primaryRecordHash: Hex64Schema,
  primaryEpoch: z.number().int().nonnegative(),
  primaryOnline: z.boolean(),
  observedAt: z.number().int().nonnegative(),
  expiresAt: z.number().int().positive(),
}).strict();

export const SignedBridgeWitnessSchema = z.object({
  payload: BridgeWitnessPayloadSchema,
  publicKey: PublicKeySchema,
  signature: SignatureSchema,
}).strict();

export type BridgeWitnessPayload = z.infer<typeof BridgeWitnessPayloadSchema>;
export type SignedBridgeWitness = z.infer<typeof SignedBridgeWitnessSchema>;

export const IceAccessProofPayloadSchema = z.object({
  version: z.literal(ICE_ACCESS_PROOF_VERSION),
  sessionId: z.string().regex(/^[A-Za-z0-9_-]{32}$/),
  serverId: uuidSchema,
  hostId: hostIdSchema,
  identityId: identityIdSchema,
  devicePublicKey: PublicKeySchema,
  inviteAccessHash: Hex64Schema.optional(),
  issuedAt: timestampSchema,
  expiresAt: timestampSchema,
}).strict().refine(expiresAfterIssue, {
  path: ["expiresAt"],
  message: "expiresAt must be greater than issuedAt",
});

export const SignedIceAccessProofSchema = z.object({
  payload: IceAccessProofPayloadSchema,
  signature: SignatureSchema,
}).strict();

export type IceAccessProofPayload = z.infer<typeof IceAccessProofPayloadSchema>;
export type SignedIceAccessProof = z.infer<typeof SignedIceAccessProofSchema>;

export const BridgePairingTokenSchema = z.string()
  .min(80)
  .max(512)
  .regex(/^JCP1\.[A-Za-z0-9_-]{32,384}\.[A-Za-z0-9_-]{43}$/, "invalid one-time pairing token");

/** Private one-time bridge pairing document. Never embed in JC3 or signed host records. */
export const BridgePairingSchema = z.object({
  schema: z.literal("janjacord.bridge-pairing.v1"),
  descriptor: SignedBridgeDescriptorSchema,
  pairingToken: BridgePairingTokenSchema,
  pairingKeyId: z.string().regex(/^sha256:[0-9a-f]{64}$/),
}).strict();

export type BridgePairing = z.infer<typeof BridgePairingSchema>;

/** Private runtime binding passed separately from the public descriptor. */
export const BridgePairingBindingSchema = z.object({
  bridgeId: z.string().min(1).max(128),
  pairingToken: BridgePairingTokenSchema,
}).strict();

export type BridgePairingBinding = z.infer<typeof BridgePairingBindingSchema>;

export const InviteV3PayloadSchema = z
  .object({
    version: z.literal(INVITE_V3_VERSION),
    serverId: uuidSchema,
    authorityFingerprint: AuthorityFingerprintSchema,
    inviteSecret: z.string().regex(/^[A-Za-z0-9_-]{22}$/, "invite secret must encode exactly 16 bytes"),
    bridgeHints: z.array(SignedBridgeDescriptorSchema).max(MAX_BRIDGE_HINTS),
    issuedAt: timestampSchema,
    expiresAt: timestampSchema,
  })
  .strict()
  .refine(expiresAfterIssue, {
    path: ["expiresAt"],
    message: "expiresAt must be greater than issuedAt",
  });

export type InviteV3Payload = z.infer<typeof InviteV3PayloadSchema>;

export const SignedInviteV3Schema = z
  .object({
    payload: InviteV3PayloadSchema,
    publicKey: PublicKeySchema,
    signature: SignatureSchema,
  })
  .strict();

export type SignedInviteV3 = z.infer<typeof SignedInviteV3Schema>;

export const HostCapabilitySchema = z.enum(["register", "replicate", "promote"]);
export type HostCapability = z.infer<typeof HostCapabilitySchema>;

const hostCapabilitiesSchema = z
  .array(HostCapabilitySchema)
  .min(1)
  .max(HostCapabilitySchema.options.length)
  .refine((capabilities) => new Set(capabilities).size === capabilities.length, {
    message: "capabilities must be unique",
  });

export const HostGrantPayloadSchema = z
  .object({
    version: z.literal(HOST_GRANT_VERSION),
    grantId: uuidSchema,
    serverId: uuidSchema,
    issuerIdentityId: identityIdSchema,
    subjectIdentityId: identityIdSchema,
    subjectAuthPublicKey: PublicKeySchema,
    devicePublicKey: PublicKeySchema,
    hostId: hostIdSchema,
    capabilities: hostCapabilitiesSchema,
    witnessBridgeIds: z.array(z.string().min(1).max(128)).min(2).max(MAX_BRIDGE_HINTS)
      .refine((bridgeIds) => new Set(bridgeIds).size === bridgeIds.length, {
        message: "witness bridge ids must be unique",
      }).optional(),
    generation: z.number().int().positive(),
    issuedAt: timestampSchema,
    expiresAt: timestampSchema,
  })
  .strict()
  .refine(expiresAfterIssue, {
    path: ["expiresAt"],
    message: "expiresAt must be greater than issuedAt",
  });

export type HostGrantPayload = z.infer<typeof HostGrantPayloadSchema>;

export const SignedHostGrantSchema = z
  .object({
    payload: HostGrantPayloadSchema,
    publicKey: PublicKeySchema,
    signature: SignatureSchema,
  })
  .strict();

export type SignedHostGrant = z.infer<typeof SignedHostGrantSchema>;

export const HostGrantRevocationPayloadSchema = z
  .object({
    version: z.literal(HOST_GRANT_REVOCATION_VERSION),
    serverId: uuidSchema,
    grantId: uuidSchema,
    hostId: hostIdSchema,
    issuerIdentityId: identityIdSchema,
    revokedAt: timestampSchema,
    generation: z.number().int().positive(),
    reason: z.string().min(1).max(512).optional(),
  })
  .strict();

export type HostGrantRevocationPayload = z.infer<typeof HostGrantRevocationPayloadSchema>;

export const SignedHostGrantRevocationSchema = z
  .object({
    payload: HostGrantRevocationPayloadSchema,
    publicKey: PublicKeySchema,
    signature: SignatureSchema,
  })
  .strict();

export type SignedHostGrantRevocation = z.infer<typeof SignedHostGrantRevocationSchema>;

export const HostRoleSchema = z.enum(["primary", "replica"]);
export type HostRole = z.infer<typeof HostRoleSchema>;

export const HostRecordPayloadSchema = z
  .object({
    version: z.literal(HOST_RECORD_VERSION),
    serverId: uuidSchema,
    grantId: uuidSchema,
    hostId: hostIdSchema,
    role: HostRoleSchema,
    epoch: z.number().int().nonnegative(),
    recordSeq: z.number().int().positive(),
    previousRecordHash: z.string().regex(/^[0-9a-f]{64}$/).nullable(),
    endpoints: z.array(endpointSchema).max(MAX_CONNECTIVITY_ENDPOINTS),
    candidates: z.array(iceCandidateSchema).max(MAX_ICE_CANDIDATES),
    issuedAt: timestampSchema,
    ttlMs: z.number().int().positive(),
    expiresAt: timestampSchema,
  })
  .strict()
  .refine((record) => record.endpoints.length + record.candidates.length > 0, {
    path: ["endpoints"],
    message: "host record must advertise at least one endpoint or ICE candidate",
  })
  .refine(expiresAfterIssue, {
    path: ["expiresAt"],
    message: "expiresAt must be greater than issuedAt",
  });

export type HostRecordPayload = z.infer<typeof HostRecordPayloadSchema>;

export const SignedHostRecordSchema = z
  .object({
    payload: HostRecordPayloadSchema,
    publicKey: PublicKeySchema,
    signature: SignatureSchema,
  })
  .strict();

export type SignedHostRecord = z.infer<typeof SignedHostRecordSchema>;

export const HostRegistrationSchema = z.object({
  authorityPublicKey: PublicKeySchema,
  grant: SignedHostGrantSchema,
  record: SignedHostRecordSchema,
}).strict();

export type HostRegistration = z.infer<typeof HostRegistrationSchema>;

export const SessionAuthPayloadSchema = z
  .object({
    version: z.literal(SESSION_AUTH_VERSION),
    serverId: uuidSchema,
    identityId: identityIdSchema,
    publicKey: PublicKeySchema,
    challengeId: uuidSchema,
    nonce: Base64UrlSchema,
    issuedAt: timestampSchema,
    expiresAt: timestampSchema,
  })
  .strict()
  .refine(expiresAfterIssue, {
    path: ["expiresAt"],
    message: "expiresAt must be greater than issuedAt",
  });

export type SessionAuthPayload = z.infer<typeof SessionAuthPayloadSchema>;

export const SignedSessionAuthSchema = z.object({
  payload: SessionAuthPayloadSchema,
  signature: SignatureSchema,
}).strict();

export type SignedSessionAuth = z.infer<typeof SignedSessionAuthSchema>;

export const HostAuthChallengePayloadSchema = z.object({
  version: z.literal(HOST_AUTH_CHALLENGE_VERSION),
  serverId: uuidSchema,
  authorityFingerprint: AuthorityFingerprintSchema,
  hostId: hostIdSchema,
  grantId: uuidSchema,
  challengeId: uuidSchema,
  nonce: Base64UrlSchema,
  issuedAt: timestampSchema,
  expiresAt: timestampSchema,
}).strict().refine(expiresAfterIssue, {
  path: ["expiresAt"],
  message: "expiresAt must be greater than issuedAt",
});

export type HostAuthChallengePayload = z.infer<typeof HostAuthChallengePayloadSchema>;

export const SignedHostAuthChallengeSchema = z.object({
  payload: HostAuthChallengePayloadSchema,
  publicKey: PublicKeySchema,
  signature: SignatureSchema,
}).strict();

export type SignedHostAuthChallenge = z.infer<typeof SignedHostAuthChallengeSchema>;

export const BridgeRegistrationChallengeSchema = z.object({
  requestId: uuidSchema,
  challengeId: uuidSchema,
  nonce: Base64UrlSchema,
  recordHash: z.string().regex(/^[0-9a-f]{64}$/),
  expiresAt: timestampSchema,
}).strict();

export type BridgeRegistrationChallenge = z.infer<typeof BridgeRegistrationChallengeSchema>;

export const BridgeRegistrationProofPayloadSchema = z.object({
  version: z.literal(BRIDGE_REGISTRATION_PROOF_VERSION),
  serverId: uuidSchema,
  hostId: hostIdSchema,
  grantId: uuidSchema,
  recordHash: z.string().regex(/^[0-9a-f]{64}$/),
  challengeId: uuidSchema,
  nonce: Base64UrlSchema,
  issuedAt: timestampSchema,
  expiresAt: timestampSchema,
}).strict().refine(expiresAfterIssue, {
  path: ["expiresAt"],
  message: "expiresAt must be greater than issuedAt",
});

export type BridgeRegistrationProofPayload = z.infer<typeof BridgeRegistrationProofPayloadSchema>;

export const SignedBridgeRegistrationProofSchema = z.object({
  payload: BridgeRegistrationProofPayloadSchema,
  publicKey: PublicKeySchema,
  signature: SignatureSchema,
}).strict();

export type SignedBridgeRegistrationProof = z.infer<typeof SignedBridgeRegistrationProofSchema>;
