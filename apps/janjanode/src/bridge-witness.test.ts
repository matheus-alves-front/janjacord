import { describe, expect, it } from "vitest";
import { ed25519Fingerprint, ed25519PublicKey } from "@janjacord/crypto";
import { createSignedBridgeDescriptor, createSignedBridgeWitness } from "@janjacord/protocol";
import { validateBridgeWitnessResponse } from "./bridge-witness.js";

const SERVER_ID = "11111111-1111-4111-8111-111111111111";

describe("bridge witness response binding", () => {
  it("accepts only the descriptor key and exact request/primary/epoch/hash/time binding", () => {
    const seed = Buffer.alloc(32, 91);
    const now = 100_000;
    const bridgeId = `ed25519:${ed25519Fingerprint(ed25519PublicKey(seed))}`;
    const descriptor = createSignedBridgeDescriptor({
      version: 1,
      bridgeId,
      endpoints: ["wss://bridge.example/rendezvous"],
      issuedAt: now - 1_000,
      expiresAt: now + 60_000,
    }, seed);
    const expected = {
      requestId: "22222222-2222-4222-8222-222222222222",
      serverId: SERVER_ID,
      replicaHostId: "replica-a",
      primaryHostId: "primary-a",
      primaryRecordHash: "ab".repeat(32),
      primaryEpoch: 7,
    };
    const witness = createSignedBridgeWitness({
      version: 1,
      bridgeId,
      ...expected,
      primaryOnline: false,
      observedAt: now,
      expiresAt: now + 5_000,
    }, seed);

    expect(validateBridgeWitnessResponse(witness, descriptor, expected, now + 1)).toMatchObject({
      bridgeId, primaryOnline: false, primaryEpoch: 7,
    });
    expect(validateBridgeWitnessResponse(witness, descriptor, { ...expected, requestId: "33333333-3333-4333-8333-333333333333" }, now + 1)).toBeNull();
    expect(validateBridgeWitnessResponse(witness, descriptor, { ...expected, primaryRecordHash: "cd".repeat(32) }, now + 1)).toBeNull();
    expect(validateBridgeWitnessResponse(witness, descriptor, { ...expected, primaryEpoch: 8 }, now + 1)).toBeNull();
    expect(validateBridgeWitnessResponse(witness, descriptor, expected, now + 10_001)).toBeNull();
  });
});
