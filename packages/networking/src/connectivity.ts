import type { HostRegistration, SignedHostGrant, SignedHostRecord } from "@janjacord/schemas";
import { HostRegistrationSchema } from "@janjacord/schemas";
import { ed25519Fingerprint } from "@janjacord/crypto";
import { verifyHostRegistration } from "@janjacord/protocol";

export interface VerifiedHostAuthenticationContext {
  authorityFingerprint: string;
  authorityPublicKey: string;
  hostPublicKey: string;
  serverId: string;
  hostId: string;
  grantId: string;
  record: SignedHostRecord;
  grant: SignedHostGrant;
}

/** Verifies the complete resolve chain before any session-auth frame is trusted. */
export function verifyHostAuthenticationContext(
  value: unknown,
  expected: {
    serverId: string;
    authorityFingerprint: string;
    hostId?: string;
    now?: number;
  },
): VerifiedHostAuthenticationContext | null {
  const parsed = HostRegistrationSchema.safeParse(value);
  if (!parsed.success) return null;
  const registration: HostRegistration = parsed.data;
  let authorityFingerprint: string;
  try {
    authorityFingerprint = ed25519Fingerprint(Buffer.from(registration.authorityPublicKey, "base64url"));
  } catch {
    return null;
  }
  if (authorityFingerprint !== expected.authorityFingerprint.toLowerCase()) return null;
  const verified = verifyHostRegistration({
    record: registration.record,
    grant: registration.grant,
    authorityPublicKey: registration.authorityPublicKey,
    now: expected.now,
  });
  if (!verified || verified.record.payload.serverId !== expected.serverId) return null;
  if (expected.hostId && verified.record.payload.hostId !== expected.hostId) return null;
  return {
    authorityFingerprint,
    authorityPublicKey: registration.authorityPublicKey,
    hostPublicKey: verified.record.publicKey,
    serverId: verified.record.payload.serverId,
    hostId: verified.record.payload.hostId,
    grantId: verified.record.payload.grantId,
    ...verified,
  };
}
