import { describe, expect, it } from "vitest";
import { strictBridgeWitnessQuorum } from "./server.service.js";
import { RegistrationAckQuorum, RegistrationWriteAuthorityLease } from "./registration-quorum.js";

describe("RegistrationAckQuorum", () => {
  it("requires the sole configured bridge instead of treating one bridge as an implicit quorum", () => {
    const quorum = new RegistrationAckQuorum(["bridge-a"]);
    const binding = { recordHash: "c".repeat(64), epoch: 1, role: "primary" as const };
    quorum.begin(binding);
    expect(quorum.hasStrictQuorum(binding)).toBe(false);
    expect(quorum.acknowledge("bridge-a", binding)).toBe(true);
    expect(quorum.hasStrictQuorum(binding)).toBe(true);
  });

  it("does not count an old replica ACK after promotion to a new primary record", () => {
    const quorum = new RegistrationAckQuorum(["bridge-a", "bridge-b"]);
    const oldReplica = { recordHash: "a".repeat(64), epoch: 4, role: "replica" as const };
    quorum.begin(oldReplica);
    expect(quorum.acknowledge("bridge-a", oldReplica)).toBe(true);

    const promoted = { recordHash: "b".repeat(64), epoch: 5, role: "primary" as const };
    quorum.begin(promoted);
    expect(quorum.acknowledge("bridge-b", oldReplica)).toBe(false);
    expect(quorum.count(promoted)).toBe(0);
    expect(quorum.hasStrictQuorum(promoted)).toBe(false);
    expect(quorum.acknowledge("bridge-a", promoted)).toBe(true);
    expect(quorum.count(promoted)).toBe(1);
    quorum.remove("bridge-a");
    expect(quorum.count(promoted)).toBe(0);
    expect(quorum.acknowledge("bridge-a", promoted)).toBe(true);
    expect(quorum.acknowledge("bridge-b", promoted)).toBe(true);
    expect(quorum.hasStrictQuorum(promoted)).toBe(true);
  });

  it("preserves 2-bridge retention by requiring both ACKs to renew write authority", () => {
    const quorum = new RegistrationAckQuorum(["bridge-a", "bridge-b"]);
    const lease = new RegistrationWriteAuthorityLease(quorum, 0);
    const binding = { recordHash: "d".repeat(64), epoch: 2, role: "primary" as const };
    quorum.begin(binding);

    expect(quorum.acknowledge("bridge-a", binding)).toBe(true);
    expect(lease.observe(binding, 4_000)).toBe(false);
    expect(quorum.acknowledge("bridge-b", binding)).toBe(true);
    expect(lease.observe(binding, 4_000)).toBe(true);

    expect(quorum.beginLivenessRound(binding, "round-1")).toBe(true);
    expect(quorum.confirmLiveness("bridge-a", binding, "round-1")).toBe(true);
    expect(lease.observe(binding, 5_000)).toBe(false);
    expect(quorum.confirmLiveness("bridge-b", binding, "round-1")).toBe(true);
    expect(lease.observe(binding, 5_000)).toBe(true);

    expect(quorum.beginLivenessRound(binding, "round-2")).toBe(true);
    expect(quorum.confirmLiveness("bridge-a", binding, "round-2")).toBe(true);
    expect(lease.observe(binding, 19_999)).toBe(false);
    expect(lease.shouldFence(15_000, 19_999)).toBe(false);
    expect(lease.shouldFence(15_000, 20_000)).toBe(true);
  });

  it("never accepts concurrent writes when Primary sees only A and candidate sees B+C", () => {
    const bridges = ["bridge-a", "bridge-b", "bridge-c"];
    const incumbentQuorum = new RegistrationAckQuorum(bridges);
    const incumbentLease = new RegistrationWriteAuthorityLease(incumbentQuorum, 0);
    const binding = { recordHash: "e".repeat(64), epoch: 7, role: "primary" as const };
    incumbentQuorum.begin(binding);

    for (const bridge of bridges) expect(incumbentQuorum.acknowledge(bridge, binding)).toBe(true);
    expect(incumbentLease.observe(binding, 0)).toBe(true);

    let incumbentWriter = true;
    let candidateWriter = false;
    let fenceCalls = 0;
    const acceptedWrites: { at: number; writer: "incumbent" | "candidate" }[] = [];
    const witnessAbsenceGraceMs = 30_000;

    for (let now = 1_000; now <= 35_000; now += 1_000) {
      const livenessRound = `liveness-${now}`;
      expect(incumbentQuorum.beginLivenessRound(binding, livenessRound)).toBe(true);
      // A remains reachable from the old Primary. B+C have disconnected at t=0 and are the
      // candidate's witness majority, so only A can answer incumbent liveness challenges.
      expect(incumbentQuorum.confirmLiveness("bridge-a", binding, livenessRound)).toBe(true);
      expect(incumbentLease.observe(binding, now)).toBe(false);

      incumbentLease.fenceIfQuorumExpired(15_000, () => {
        if (!incumbentWriter) return false;
        fenceCalls += 1;
        incumbentWriter = false;
        return true;
      }, now);

      if (now >= witnessAbsenceGraceMs) {
        candidateWriter = strictBridgeWitnessQuorum(3, [null, false, false]);
      }

      if (incumbentWriter) acceptedWrites.push({ at: now, writer: "incumbent" });
      if (candidateWriter) acceptedWrites.push({ at: now, writer: "candidate" });
      const acceptedNow = acceptedWrites.filter((write) => write.at === now);
      expect(new Set(acceptedNow.map((write) => write.writer)).size).toBeLessThanOrEqual(1);
    }

    expect(fenceCalls).toBe(1);
    expect(acceptedWrites.some((write) => write.writer === "incumbent" && write.at < 15_000)).toBe(true);
    expect(acceptedWrites.some((write) => write.writer === "incumbent" && write.at >= 15_000)).toBe(false);
    expect(acceptedWrites.some((write) => write.writer === "candidate" && write.at < witnessAbsenceGraceMs)).toBe(false);
    expect(acceptedWrites.some((write) => write.writer === "candidate" && write.at >= witnessAbsenceGraceMs)).toBe(true);
    expect([incumbentWriter, candidateWriter].filter(Boolean)).toHaveLength(1);
    expect(candidateWriter).toBe(true);
  });
});
