# SPEC — Realtime Networking Protocol

## 1. Slice identity

- Slice / feature / artifact: protocolo de transporte realtime (mensagens, signaling, entrega)
- Current phase: Phase 0-1 — definição (TASK-001)
- Target repo or artifact: `specs/` + `packages/protocol,networking,realtime` (futuro)
- Product truth source: PRODUCT.md §2 (Text; Network privacy), contrato congelado §19-§21
- Architecture truth source: ARCHITECTURE.md (wire protocol; transport abstraction)
- Checklist phase/item: Phase 1 (protocolo), Phase 3 (text), Phase 4 (realtime)
- Primary actor / audience: clientes (desktop/mobile) e JanjaNode
- Final-user outcome: mensagens entregues em tempo real entre peers online; spool para offline;
  sem plaintext no transporte
- Why this matters now: wire protocol é a base de tudo — precisa ser versionado e seguro antes do código

## 2. Confirmed facts (pesquisa 2026-08-09 — WebRtcScout)

- DataChannel = SCTP sobre DTLS sobre ICE/UDP (RFC 8831); DTLS protege transporte par-a-par;
  NÃO substitui E2EE de grupo (MLS) da camada de app.
- Chat efêmero read-once → **reliable + ordered** (perder mensagem quebra semântica read-once;
  RFC 8831 U-C5). Estado efêmero de voz/presença → unreliable (`maxRetransmits: 0`/
  `maxPacketLifeTime`; RFC 8831 U-C1/U-C2).
- Tamanho de mensagem: browsers ≥ 256 KiB; default 64 KiB se `max-message-size` ausente
  (RFC 8841); **fragmentar mensagens grandes (teto prático 16–64 KiB)** + backpressure via
  `bufferedAmount`/`bufferedamountlow`.
- DataChannel NÃO cobre peers offline (sem PeerConnection não há DC) → host spool de ciphertext
  com TTL + read-once/purge é protocolo de app.
- Electron: WebRTC nativo no renderer; signaling app-level via WebSocket próprio.
- JanjaNode: `node-datachannel` para DC (spool/entrega) — host não participa de media na V1.
- Desktop/mobile expõem mesma semântica WebRTC → wrapper fino em `packages/networking`
  (RTCPeerConnection, RTCDataChannel, MediaStream) compartilha lógica mesh/signaling.

## 3. Open decisions

- Wire protocol formato (binário vs JSON): binário compacto para envelope/control (CBOR ou
  length-prefixed) + JSON para signaling; decisão na Phase 1 com o architect (performance +
  parsing em RN). Blocking: sim.
- Versioning: header `protocolVersion` obrigatório em todo frame; negociação de versão no
  handshake; upgrade/migração documentada (ADR protocol versioning). Blocking: sim.
- Ordenação: ordem de entrega por canal (host atribui sequência ao spool; P2P usa ordem de DC);
  reconciliar ordenação P2P vs spool no reconnect (sequência por canal por remetente).
  Blocking: sim.
- Replay protection: messageId único (UUIDv4) + nonce; host mantém TTL curto de ids recentes
  (anti-replay mínimo justificado; sem tombstone infinito). Blocking: sim.
- Transport abstraction: DirectTransport (DC P2P) / HostTransport (spool WebSocket) /
  RelayTransport (TURN-only) — confirmar interface em `packages/networking` (ADR).

## 4. Real behavior contract

- Entry point: cliente conecta (signaling WebSocket) e/ou estabelece DC com peers.
- Main actions:
  1. Handshake: versão do protocolo, autenticação da identidade (proof de posse da device key),
     estado do canal.
  2. Envio de mensagem: envelope (messageId, channelId, epoch, audience commitment, ciphertext,
     refs de attachment) → DC reliable/ordered (online) + spool host (offline).
  3. Recepção: valida versão/messageId/nonce → entrega ao app → consumo (ver spec purge).
  4. Signaling (calls): SDP/candidates via WebSocket com perfect negotiation.
  5. Presença efêmera: ONLINE/OFFLINE/IN_CALL (DC unreliable ou signaling).
- Data required: identidade, server/channel state, envelope, candidatos ICE.
- Persistence or side effect: ciphertext temporário no host spool; nada permanente.
- Integrations/API calls: DataChannel, WebSocket, STUN/TURN, MLS (envelope).
- Completion state: envelope entregue (P2P ou spool) com integridade e sem replay.
- What must not be mocked: transporte real (não simulado), autenticação real, versioning real.

## 5. Required states and failures

- Loading: handshake; drenagem de spool no reconnect.
- Empty: n/a.
- Error: versão incompatível → erro de upgrade; mensagem corrompida → descartar com log local.
- Invalid input: frame malformado → rejeição silenciosa (rate-limited).
- Unauthorized: identidade sem permissão no canal → rejeição.
- Slow dependency: spool lento; TURN sobrecarregado.
- Partial failure: DC cai → spool host assume; reconnect drena spool ordenadamente.
- Retry/recovery: messageId idempotente (reentrega não duplica); backoff no handshake;
  host reinicia → spool preservado (SQLite cifrado) e re-drenado.

## 6. Acceptance criteria

- [ ] Envelope versionado trafega P2P (DC) e via spool (WebSocket) com o mesmo formato
- [ ] Fragmentação < 64 KiB + reassembly correto; backpressure respeitada (bufferedAmount)
- [ ] Replay de messageId/nonce rejeitado (host TTL curto)
- [ ] Mensagem fora da audiência não é entregue (verificação no host e no cliente)
- [ ] Ordenação consistente P2P + spool no reconnect
- [ ] Handshake autentica identidade (proof de posse) antes de aceitar frames
- [ ] Host só recebe ciphertext (nunca plaintext)

## 7. Mock and placeholder policy

- Allowed only as internal draft: mock transport em testes unitários (não em operator test).
- Explicitly blocked for final: transporte fake em milestone M1 (contrato LOCKED).
- Label required if mock remains: `MOCK`.
- Follow-up required before release: nenhum.

## 8. Client/public language gate

- Terms that must not appear: "websocket", "SDP", termos técnicos na UI.
- Claims that require proof: "nenhum plaintext no transporte" — testes.
- Buyer/client language replacements: n/a (protocolo é interno; docs públicas técnicas).

## 9. (não aplicável)

## 10. Evidence required before checklist completion

- Testes de protocolo (versioning, replay, fragmentação, ordenação)
- Teste de autenticação de handshake
- Operator-test M1: transporte real P2P + spool

## 11. Checklist projection

- Checklist file: CHECKLIST.md — Phase 1, Phase 3
- Item(s): wire protocol v0, transport abstraction, handshake, ordering, replay
- Acceptance rule: `[x]` com testes de protocolo + operator-test M1
- Evidence links: QA-REVIEW; OPERATOR-TEST-PACKET-MVP

## 12. Source docs touched

- PRODUCT.md: sim
- ARCHITECTURE.md: sim (wire protocol; transport)
- INTEGRATIONS.md: sim (WebRTC/DC, node-datachannel)
- ADR required: ADR (protocol versioning), ADR-006 (mesh)
- Operator packet required: sim (M1)
