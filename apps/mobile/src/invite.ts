/**
 * Parse do convite do JanjaCord no mobile (JC1/JC2).
 * Espelha packages/crypto (toBase32/fromBase32/parseInviteKey) sem depender do
 * node:crypto (não existe no Hermes). JC2 carrega o endpoint: cola só a key.
 */
const B32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

function fromBase32(input: string): Uint8Array {
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of input.toUpperCase()) {
    const idx = B32_ALPHABET.indexOf(ch);
    if (idx < 0) throw new Error("invalid base32 char");
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Uint8Array.from(out);
}

export interface ParsedInvite {
  serverId: string;
  secretHex: string;
  /** "host:porta" embutido (JC2) — undefined em JC1. */
  endpoint?: string;
}

const SEG = 26;

export function parseInvite(key: string): ParsedInvite | null {
  const m = key.trim().match(/^JC([12])-([A-Za-z2-7]+(?:-[A-Za-z2-7]+)*)$/);
  if (!m) return null;
  const version = m[1]!;
  try {
    const compact = m[2]!.replace(/-/g, "");
    if (version === "1" && compact.length !== SEG * 2) return null;
    if (version === "2" && compact.length < SEG * 2) return null;
    const sid = fromBase32(compact.slice(-SEG * 2, -SEG));
    const secret = fromBase32(compact.slice(-SEG));
    if (sid.length !== 16 || secret.length !== 16) return null;
    const hex = Array.from(sid, (b) => b.toString(16).padStart(2, "0")).join("");
    const serverId = `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
    const epB32 = compact.slice(0, -SEG * 2);
    if (version === "2" && !epB32) return null;
    const endpoint = epB32
      ? new TextDecoder().decode(fromBase32(epB32))
      : undefined;
    const secretHex = Array.from(secret, (b) => b.toString(16).padStart(2, "0")).join("");
    return { serverId, secretHex, endpoint };
  } catch {
    return null;
  }
}

/** ws://<endpoint>/signal — ou null se o convite não carrega endpoint. */
export function endpointFromInvite(inviteKey: string): string | null {
  const p = parseInvite(inviteKey);
  return p?.endpoint ? `ws://${p.endpoint}/signal` : null;
}
