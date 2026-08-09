import { randomUUID } from "node:crypto";
import {
  MessageEnvelopeSchema,
  type MessageEnvelope,
  PROTOCOL_VERSION,
  MAX_FRAME_BYTES,
  type AttachmentRef,
} from "@janjacord/schemas";

/**
 * Wire protocol v0 (ADR-013): envelope versionado, fragmentação, anti-replay.
 * JSON como formato canônico (binário otimizado fica como evolução versionada).
 */

export function newMessageId(): string {
  return randomUUID();
}

export function encodeEnvelope(envelope: MessageEnvelope): string {
  const parsed = MessageEnvelopeSchema.parse(envelope);
  return JSON.stringify(parsed);
}

export function decodeEnvelope(raw: string): MessageEnvelope {
  return MessageEnvelopeSchema.parse(JSON.parse(raw));
}

/** Fragmentação (RFC 8841 default 64KiB): teto prático do DataChannel (ADR-013). */
export interface Fragment {
  messageId: string;
  index: number;
  total: number;
  data: Uint8Array;
}

export function fragmentMessage(messageId: string, data: Uint8Array, maxBytes = MAX_FRAME_BYTES): Fragment[] {
  const total = Math.max(1, Math.ceil(data.length / maxBytes));
  const out: Fragment[] = [];
  for (let i = 0; i < total; i++) {
    out.push({
      messageId,
      index: i,
      total,
      data: data.subarray(i * maxBytes, (i + 1) * maxBytes),
    });
  }
  return out;
}

export function defragment(fragments: Fragment[]): Uint8Array {
  if (fragments.length === 0) throw new Error("no fragments");
  const total = fragments[0]!.total;
  if (fragments.length !== total) throw new Error(`incomplete fragments ${fragments.length}/${total}`);
  const sorted = [...fragments].sort((a, b) => a.index - b.index);
  let size = 0;
  for (const f of sorted) size += f.data.length;
  const out = new Uint8Array(size);
  let off = 0;
  for (const f of sorted) {
    out.set(f.data, off);
    off += f.data.length;
  }
  return out;
}

export function encodeFragment(f: Fragment): string {
  return JSON.stringify({ messageId: f.messageId, index: f.index, total: f.total, data: Buffer.from(f.data).toString("base64") });
}

export function decodeFragment(raw: string): Fragment {
  const p = JSON.parse(raw) as { messageId: string; index: number; total: number; data: string };
  return { messageId: p.messageId, index: p.index, total: p.total, data: Uint8Array.from(Buffer.from(p.data, "base64")) };
}

/**
 * Anti-replay (ADR-013): janela deslizante de messageIds com TTL curto no host.
 * Sem tombstone infinito — o TTL é o máximo de retenção da mensagem.
 */
export class ReplayGuard {
  private seen = new Map<string, number>();

  constructor(
    private readonly ttlMs: number,
    private readonly clock: () => number = Date.now,
  ) {}

  /** true = aceito; false = replay detectado. */
  check(messageId: string): boolean {
    const now = this.clock();
    // limpeza lazy
    for (const [id, t] of this.seen) {
      if (now - t > this.ttlMs) this.seen.delete(id);
    }
    if (this.seen.has(messageId)) return false;
    this.seen.set(messageId, now);
    return true;
  }

  size(): number {
    return this.seen.size;
  }
}

/** Ordenação por canal/remetente: sequência monótona por remetente (ADR-013). */
export class SequenceTracker {
  private seq = new Map<string, number>();

  next(sender: string): number {
    const v = (this.seq.get(sender) ?? 0) + 1;
    this.seq.set(sender, v);
    return v;
  }

  last(sender: string): number {
    return this.seq.get(sender) ?? 0;
  }
}

/** Builder de envelope com valores default (seq/createdAt/expiresAt). */
export function buildEnvelope(input: {
  serverId: string;
  channelId: string;
  sender: string;
  senderDevice?: string;
  cryptoEpoch: number;
  audience: MessageEnvelope["audience"];
  ciphertext: string;
  attachments?: AttachmentRef[];
  ordering: MessageEnvelope["ordering"];
  expiresAt?: number;
}): MessageEnvelope {
  return MessageEnvelopeSchema.parse({
    protocolVersion: PROTOCOL_VERSION,
    messageId: newMessageId(),
    createdAt: Date.now(),
    ...input,
  });
}
