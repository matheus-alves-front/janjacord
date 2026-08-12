export interface RegistrationAckBinding {
  recordHash: string;
  epoch: number;
  role: "primary" | "replica";
}

function bindingKey(binding: RegistrationAckBinding): string {
  return `${binding.recordHash}\0${binding.epoch}\0${binding.role}`;
}

/** ACKs are valid only for one exact signed-record round and never survive a role/epoch change. */
export class RegistrationAckQuorum {
  private activeKey: string | null = null;
  private acknowledgements = new Set<string>();
  private activeLivenessRound: string | null = null;
  private liveAcknowledgements = new Set<string>();

  constructor(private readonly bridgeIds: readonly string[]) {
    if (bridgeIds.length < 1 || bridgeIds.length > 3 || new Set(bridgeIds).size !== bridgeIds.length) {
      throw new Error("registration quorum requires one to three unique bridge ids");
    }
  }

  begin(binding: RegistrationAckBinding): void {
    const next = bindingKey(binding);
    if (next === this.activeKey) return;
    this.activeKey = next;
    this.acknowledgements.clear();
    this.activeLivenessRound = null;
    this.liveAcknowledgements.clear();
  }

  acknowledge(bridgeId: string, binding: RegistrationAckBinding): boolean {
    if (!this.bridgeIds.includes(bridgeId) || bindingKey(binding) !== this.activeKey) return false;
    this.acknowledgements.add(bridgeId);
    // The registration ACK itself is fresh liveness evidence for the active round.
    this.liveAcknowledgements.add(bridgeId);
    return true;
  }

  beginLivenessRound(binding: RegistrationAckBinding, roundId: string): boolean {
    if (!roundId || bindingKey(binding) !== this.activeKey) return false;
    this.activeLivenessRound = roundId;
    this.liveAcknowledgements.clear();
    return true;
  }

  confirmLiveness(bridgeId: string, binding: RegistrationAckBinding, roundId: string): boolean {
    if (bindingKey(binding) !== this.activeKey || roundId !== this.activeLivenessRound
      || !this.acknowledgements.has(bridgeId)) return false;
    this.liveAcknowledgements.add(bridgeId);
    return true;
  }

  clear(): void {
    this.activeKey = null;
    this.acknowledgements.clear();
    this.activeLivenessRound = null;
    this.liveAcknowledgements.clear();
  }

  remove(bridgeId: string): void {
    this.acknowledgements.delete(bridgeId);
    this.liveAcknowledgements.delete(bridgeId);
  }

  hasStrictQuorum(binding: RegistrationAckBinding): boolean {
    return bindingKey(binding) === this.activeKey
      && this.acknowledgements.size >= Math.floor(this.bridgeIds.length / 2) + 1;
  }

  hasStrictLiveQuorum(binding: RegistrationAckBinding): boolean {
    return bindingKey(binding) === this.activeKey
      && this.liveAcknowledgements.size >= Math.floor(this.bridgeIds.length / 2) + 1;
  }

  count(binding: RegistrationAckBinding): number {
    return bindingKey(binding) === this.activeKey ? this.acknowledgements.size : 0;
  }
}

/**
 * Bounded write-authority lease renewed only by an intersecting strict majority of the
 * configured bridge set. Minority ACKs are intentionally unable to extend the lease.
 */
export class RegistrationWriteAuthorityLease {
  private lastStrictQuorumAt: number;

  constructor(
    private readonly quorum: RegistrationAckQuorum,
    initialProofAt = Date.now(),
  ) {
    this.lastStrictQuorumAt = initialProofAt;
  }

  reset(now = Date.now()): void {
    this.lastStrictQuorumAt = now;
  }

  observe(binding: RegistrationAckBinding, now = Date.now()): boolean {
    if (!this.quorum.hasStrictLiveQuorum(binding)) return false;
    this.lastStrictQuorumAt = now;
    return true;
  }

  shouldFence(timeoutMs: number, now = Date.now()): boolean {
    return now - this.lastStrictQuorumAt >= timeoutMs;
  }

  fenceIfQuorumExpired(
    timeoutMs: number,
    fenceWriter: () => boolean,
    now = Date.now(),
  ): boolean {
    return this.shouldFence(timeoutMs, now) && fenceWriter();
  }
}
