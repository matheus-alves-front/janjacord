/**
 * Smoke relay-only (ADR-007): com iceTransportPolicy='relay', NENHUM candidate
 * host/srflx pode ser emitido — só relay (TURN). Sem TURN real, o gathering
 * não produz candidates usáveis, mas a VERIFICAÇÃO é o enforcement de privacidade.
 */
import nodeDataChannel from "node-datachannel";

let failures = 0;
const assert = (cond, label) => {
  if (cond) console.log(`  ✓ ${label}`);
  else {
    failures++;
    console.error(`  ✗ ${label}`);
  }
};

function collectCandidates(transportPolicy) {
  return new Promise((resolve) => {
    const candidates = [];
    const pc = new nodeDataChannel.PeerConnection(`relay-${Math.random()}`, {
      iceServers: ["turn:turn.invalido.example:3478"], // TURN inexistente — só para provocar gathering
      iceTransportPolicy: transportPolicy,
      disableAutoNegotiation: false,
    });
    const timer = setTimeout(() => {
      pc.close();
      resolve(candidates);
    }, 4000);
    pc.onLocalCandidate((candidate, mid) => {
      candidates.push({ candidate, mid });
    });
    pc.createDataChannel("probe");
    pc.setLocalDescription("", "Offer");
    void timer;
  });
}

async function main() {
  console.log("[smoke-relay] policy relay — candidates…");
  const relayCandidates = await collectCandidates("relay");
  const hostLike = relayCandidates.filter((c) => /\btyp\s+(host|srflx)\b/.test(c.candidate));
  console.log(`  candidates relay-only: ${relayCandidates.length} (host/srflx: ${hostLike.length})`);
  assert(hostLike.length === 0, "nenhum candidate host/srflx com policy relay (enforcement)");
  assert(relayCandidates.every((c) => /\btyp\s+relay\b/.test(c.candidate)), "candidates restantes são do tipo relay");

  console.log("[smoke-relay] policy all (direct) — candidates…");
  const directCandidates = await collectCandidates("all");
  const hostDirect = directCandidates.filter((c) => /\btyp\s+host\b/.test(c.candidate));
  console.log(`  candidates direct: ${directCandidates.length} (host: ${hostDirect.length})`);
  assert(hostDirect.length > 0, "policy direct emite candidates host (controle)");

  if (failures === 0) console.log("[smoke-relay] RELAY-ONLY ENFORCEMENT OK");
  else console.error(`[smoke-relay] ${failures} falhas`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error("[smoke-relay] erro:", e);
  process.exit(1);
});
