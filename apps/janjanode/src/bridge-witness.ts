import type { SignedBridgeDescriptor } from "@janjacord/schemas";
import { verifySignedBridgeWitness } from "@janjacord/protocol";

export interface ValidatedBridgeWitness {
  bridgeId: string;
  requestId: string;
  primaryHostId: string;
  primaryRecordHash: string;
  primaryEpoch: number;
  primaryOnline: boolean;
  observedAt: number;
  expiresAt: number;
}

export interface ExpectedBridgeWitness {
  requestId: string;
  serverId: string;
  replicaHostId: string;
  primaryHostId: string;
  primaryRecordHash: string;
  primaryEpoch: number;
}

/** Verify the bridge signature and every field that binds one response to this request. */
export function validateBridgeWitnessResponse(
  value: unknown,
  descriptor: SignedBridgeDescriptor,
  expected: ExpectedBridgeWitness,
  now = Date.now(),
): ValidatedBridgeWitness | null {
  const verified = verifySignedBridgeWitness(value, descriptor, now);
  if (!verified) return null;
  const payload = verified.payload;
  if (payload.requestId !== expected.requestId
    || payload.bridgeId !== descriptor.payload.bridgeId
    || payload.serverId !== expected.serverId
    || payload.replicaHostId !== expected.replicaHostId
    || payload.primaryHostId !== expected.primaryHostId
    || payload.primaryRecordHash !== expected.primaryRecordHash
    || payload.primaryEpoch !== expected.primaryEpoch) return null;
  return {
    bridgeId: payload.bridgeId,
    requestId: payload.requestId,
    primaryHostId: payload.primaryHostId,
    primaryRecordHash: payload.primaryRecordHash,
    primaryEpoch: payload.primaryEpoch,
    primaryOnline: payload.primaryOnline,
    observedAt: payload.observedAt,
    expiresAt: payload.expiresAt,
  };
}
