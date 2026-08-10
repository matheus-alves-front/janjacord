# SPEC — Voice and Video over WebRTC (mesh P2P V1)

## 1. Slice identity

- Slice / feature / artifact: canais de call — voz + vídeo opcional, mesh P2P
- Current phase: Phase 0-1 — definição (TASK-001)
- Target repo or artifact: `specs/` + `packages/realtime,networking` (futuro)
- Product truth source: PRODUCT.md §2 (Voice/Video; Network privacy), contrato congelado §29-§32, §35-§37
- Architecture truth source: ARCHITECTURE.md (media lifecycle; transport)
- Checklist phase/item: Phase 4 — Realtime Voice/Video
- Primary actor / audience: membros com `join_call` em canal de call
- Final-user outcome: chamada de voz/vídeo privada em grupo, sem gravação, sem storage
- Why this matters now: segundo risco central (depois do texto E2EE); define WebRTC, NAT, limites

## 2. Confirmed facts (pesquisa 2026-08-09 — WebRtcScout)

- **Desktop (Electron):** WebRTC nativo do Chromium no renderer (`RTCPeerConnection`,
  `RTCDataChannel`, `getUserMedia`). Nada extra. `contextIsolation`/`sandbox` não bloqueiam
  WebRTC. Permissões de mídia decididas no main via `session.setPermissionRequestHandler`
  (type `media`) + `setPermissionCheckHandler`; macOS exige chaves TCC no Info.plist
  (`NSCameraUsageDescription`/`NSMicrophoneUsageDescription`) [INFERENCE — confirmar no build].
- **Mobile (React Native + Expo dev-client):** `react-native-webrtc` 124.x (libwebrtc M124,
  MIT, mantido; New Arch RN 0.76+ — Android sólido, iOS em validação). Expo Go NÃO suporta
  (nativo): usar `expo-dev-client` + config-plugin. Permissões: Android manifest
  (CAMERA/RECORD_AUDIO/etc.), iOS Info.plist (NSCamera/NSMicrophone). Alternativas maduras:
  nenhuma equivalente em 2026.
- **Node (JanjaNode):** `node-datachannel` (libdatachannel, ativo, N-API v8) para DataChannel
  (spool/entrega); host NÃO participa de media na V1. Fallback `@roamhq/wrtc` (API browser,
  libwebrtc M106).
- **Mesh:** N−1 PeerConnections por peer (10 peers ≈ 45 pares). Guardrails iniciais razoáveis:
  voice ~10, video ~6 câmeras [INFERENCE — aritmética de topologia; medir]. Simulcast
  (react-native-webrtc ≥ 111) para receptor escolher qualidade.
- **Background mobile:** iOS suspende app → `UIBackgroundModes=audio` para áudio contínuo;
  Android 14+ exige foreground service com tipo declarado (`camera`/`microphone`).
  DataChannel não flui com app suspenso → spool do host cobre offline.
- **NAT:** symmetric NAT → TURN obrigatório (RFC 8835 §3.4); firewall que bloqueia UDP →
  TURN over TCP/TLS (porta 443). Sem TURN em rede restrita, call falha.
- **DTLS protege transporte par-a-par; NÃO substitui E2EE de grupo (MLS) da camada de app.**

## 3. Open decisions

- Topologia: mesh full na V1 (LOCKED). SFU fora (ADR-006); se benchmarks provarem necessidade,
  avaliar SFU opcional self-host + SFrame (RFC 9605).
- Signaling: WebSocket próprio (rendezvous/JanjaNode) com perfect negotiation; sem lib mágica.
- Guardrails finais: benchmarks reais (LAN + WAN) antes de fixar; defaults 10 voz / 6 câmeras.

## 4. Real behavior contract

- Entry point: membro com `join_call` clica 🔊 canal → join.
- Main actions:
  1. Validação de permissão (join_call/speak/enable_camera conforme policy).
  2. Signaling: join → host coordena (quem está na call) → peers trocam SDP/candidates
     (perfect negotiation) via WebSocket.
  3. ICE: STUN (srflx) + TURN (relay fallback ou relay-only conforme policy do server).
  4. Media: mic (obrigatório p/ voice), câmera opcional (video participant); mesh P2P.
  5. Controles: mute/unmute, camera on/off, deafen, leave. Mute/deafen/leave são estado efêmero
     (DC unreliable para presence/controles).
  6. Sem gravação, sem transcrição, sem análise — nada armazenado.
- Data required: permissões, membership, ICE candidates, estado de presença na call.
- Persistence or side effect: nenhum áudio/vídeo persistido; presence efêmera (IN_CALL).
- Integrations/API calls: STUN/TURN (coturn), signaling (WebSocket), WebRTC (nativo/RN).
- Completion state: call estabelecida em mesh; leave limpa estado.
- What must not be mocked: media real entre peers (não simulada), permissão real, NAT real.

## 5. Required states and failures

- Loading: join em andamento (ICE coletando).
- Empty: ninguém na call → estado "você é o primeiro".
- Error: permissão negada (join_call); call lotada (guardrail); host offline.
- Invalid input: n/a.
- Unauthorized: sem join_call → erro claro.
- Slow dependency: STUN/TURN lento → spinner de join; reconnect com backoff.
- Partial failure: um peer cai (rede) → os demais continuam; mesh re-negocia.
- Retry/recovery: reconnect preserva a mesma policy de rede; leave → estado limpo;
  symmetric NAT sem TURN → falha clara (não congelar).

## 6. Acceptance criteria

- [ ] Call de voz entre 2+ peers atrás de NAT real (STUN direct; TURN quando necessário)
- [ ] Vídeo on/off por participante; grid responsivo reflete estado
- [ ] Mute/deafen/leave funcionam e propagam em tempo real
- [ ] Sem permissão `join_call` → bloqueado com erro claro
- [ ] Call acima do guardrail → join recusado com erro claro
- [ ] Nenhum áudio/vídeo armazenado (host não recebe media na V1)
- [ ] Nenhum candidate direto em relay-only (teste ICE)
- [ ] Benchmarks de mesh registrados (LAN + WAN; 10 voz / 6 câmeras) antes de fixar guardrails

## 7. Mock and placeholder policy

- Allowed only as internal draft: simulação de media em testes unitários de signaling.
- Explicitly blocked for final: media fake em operator test; guardrails não medidos.
- Label required if mock remains: `MOCK`.
- Follow-up required before release: benchmark real de mesh.

## 8. Client/public language gate

- Terms that must not appear: "SFU", "broadcast", "recording".
- Claims that require proof: "nada é gravado" — código + review.
- Buyer/client language replacements: "calls com privacidade", "sem gravação".

## 9. (não aplicável)

## 10. Evidence required before checklist completion

- Smoke de call real (2+ peers, NAT)
- Teste de candidates ICE (relay-only)
- Benchmark mesh (LAN + WAN) com números
- Screenshots call UI (desktop + mobile)

## 11. Checklist projection

- Checklist file: CHECKLIST.md — Phase 4
- Item(s): mesh, signaling, STUN/TURN, call UI, benchmarks
- Acceptance rule: `[x]` com smoke real + benchmarks
- Evidence links: UI-UX-EVIDENCE; QA-REVIEW; benchmark notes

## 12. Source docs touched

- PRODUCT.md: sim
- ARCHITECTURE.md: sim (media lifecycle; transport)
- INTEGRATIONS.md: sim (coturn, react-native-webrtc, node-datachannel)
- ADR required: ADR-006 (WebRTC mesh V1) + ADR-007 (direct vs relay)
- Operator packet required: sim
