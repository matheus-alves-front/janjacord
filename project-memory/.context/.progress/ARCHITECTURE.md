# ARCHITECTURE.md — JanjaCord

> Arquitetura executável por camada. Verdade durável de arquitetura (decisões em `adr/`).
> Base: research técnica 2026-08-09 (5 scouts) + contrato congelado. Nenhum código ainda.

## 0. Perfil arquitetural (resumo)

- **Domínio:** colaborativo + realtime + privacy-critical (comunicação efêmera E2EE).
- **Modelo de workspaces:** monorepo pnpm + Turborepo (single repo em
  `workspaces/janjacord/janjacord/`).
- **Composição por camada (não um slogan único):**
  - JanjaNode/backend: modular (NestJS) + ports/adapters nas fronteiras trust-sensitive
  - Desktop: feature-oriented React + strict Electron main/renderer/preload boundary
  - Mobile: feature-oriented React Native (Expo dev builds)
  - Crypto: adapter isolado sobre MLS (mls-rs core Rust; WASM/UniFFI bindings)
  - Networking: transporte por abstraction (DirectTransport/HostTransport/RelayTransport)
  - Protocolo: wire protocol versionado, independente da UI
- **Maior risco:** consistência criptográfica + segurança (identity/crypto/transporte).

## 1. Componentes e processos

```text
apps/
  desktop/      Electron (main/preload/renderer) — client + JanjaNode (host opcional)
  mobile/       React Native + Expo dev client — client
  janjanode/    NestJS — hosting/membership/signaling/spool/replica (roda no desktop quando host)
  rendezvous/   bootstrap/discovery assinado + lease/arbitragem (infra central mínima)
  push/         push service central (FCM/APNs; payload estático)   [proposta]
packages/
  domain/       entidades/regras (server, channel, membership, invites, roles)
  protocol/     wire protocol v0 (envelope, versioning, ordering, replay)
  crypto/       adapter MLS (mls-rs WASM/UniFFI) + KDF + vault helpers
  networking/   DirectTransport (DC P2P) / HostTransport (spool) / RelayTransport (TURN-only)
  realtime/     mesh/signaling/ICE wrapper (compartilhado desktop+mobile)
  permissions/  flags + precedência + channel overrides
  schemas/      Zod schemas do protocolo/domínio
  identity/     keypair, device keys, linking, recovery
  persistence/  SQLCipher (better-sqlite3 / expo-sqlite), vault file
  design-tokens/ tokens compartilhados (spacing/radius/typography/states)
  testing/      helpers de teste/protocol fuzz
infra/
  rendezvous/ stun/ turn/ docker/ release/
docs/
  protocol/ threat-model/ self-hosting/
```

- **Processos desktop:** main (Node, safeStorage, permissões, autoUpdate) / preload
  (contextBridge mínimo) / renderer (React UI + WebRTC nativo + JanjaNode quando host).
- **JanjaNode:** roda no processo do desktop (ou standalone) quando o usuário hospeda um server;
  autoridade de membership/invites/permissions/presença/signaling/spool + replicação.

## 2. Trust boundaries (críticas)

| Fronteira | Quem | Pode | Não pode |
|---|---|---|---|
| Central (rendezvous/push/STUN/TURN) | operador JanjaCord | bootstrap/connectivity; metadata mínima efêmera | ler conteúdo; telemetria de usuário |
| JanjaNode (host) | owner/peer | coordenação; ciphertext temporário | plaintext de canais que não é endpoint |
| Replica host | owner autorizado | réplica de estado/ciphertext | plaintext adicional |
| TURN/relay | operador do relay | metadata de transporte | conteúdo (E2EE) |
| Peer autorizado | membro | conteúdo do canal autorizado | conteúdo de outros canais |
| Device comprometido | atacante local | conteúdo mostrado ao usuário (limite final) | nada além |
| AS (JanjaNode assina credenciais) | host | binding ID↔device keys (RFC 9750) | conteúdo |

Princípio: **o operador da infraestrutura não precisa ser confiável para a confidencialidade do
conteúdo.** Exceção documentada: denial-of-service/atraso/observação de metadata de transporte
limitada (threat model).

## 3. Data ownership e persistência

- **Local (client):** vault cifrado (seed identidade + dbKey via KEK Argon2id), SQLite cifrado
  (SQLCipher raw key) para estado/mensagens efêmeras, cache efêmero.
- **Host (JanjaNode):** SQLite cifrado — server state (memberships, roles, channels, invites,
  crypto state) **durável**; ciphertext pendente/attachments/receipts **efêmero** com TTL.
- **Replicas:** op-log + snapshots (mesmas classes de durabilidade).
- **Central:** records efêmeros (TTL), push tokens (mínimos), TURN allocations (efêmeras).
  NUNCA: conteúdo, histórico, search index, analytics.

## 4. Crypto (boundary isolada)

- **MLS (RFC 9420)** para E2EE de grupo — `mls-rs` (awslabs, Apache-2.0/MIT) core Rust:
  - Desktop: WASM (Node main + renderer); alt: napi-rs addon
  - Mobile: UniFFI → Kotlin/Swift → TurboModule (spike obrigatório; WASM no RN NÃO é caminho)
  - Wrapper TS fino (`packages/crypto`) — nenhuma feature acessa primitiva arbitrariamente
- **Identity:** seed local 32 B (ed25519/x25519) → signature key (credencial) + HPKE
  (KeyPackage) por device; AS = JanjaNode (binding ID↔keys); device-per-leaf (revogação granular).
- **Vault:** KEK = Argon2id(senha) → AES-256-GCM blobs; SQLCipher raw key; senha nunca é
  identidade; recovery key (mnemônico/export).
- **Chaves por mensagem:** deleção após uso (FS intra-epoch RFC 9420 §16.6); purge de
  ciphertext é responsabilidade do transporte.
- Proibido: protocolo criptográfico próprio; libsignal como base de grupo (AGPL + limitações).

## 5. Wire protocol (v0)

- Envelope: protocolVersion, messageId (UUIDv4), serverId, channelId, sender identity ref,
  cryptoEpoch, audience commitment, ciphertext (PrivateMessage MLS), attachment refs,
  ordering/anti-replay, expiry. Formato exato: Phase 1 (binário compacto + JSON signaling).
- Versioning: header obrigatório; negociação no handshake; upgrade documentado.
- Ordenação: por canal/remetente (não global); reconciliação P2P↔spool no reconnect.
- Anti-replay: messageId único + nonce; host TTL curto de ids recentes (sem tombstone infinito).
- Transport: DirectTransport (DC reliable+ordered, fragmentação 16–64 KiB, backpressure via
  bufferedAmount) / HostTransport (WebSocket spool) / RelayTransport (TURN-only).

## 6. Message lifecycle (texto)

1. Sender cifra com MLS (epoch atual) → envelope → DC (online) + spool host (offline).
2. Receiver: autentica → descriptografa → renderiza no canal ativo → CONSUMED ACK (idempotente).
3. Purge: todos elegíveis consumiram → purge imediato (host+replicas+receipts); senão
   max retention (default 7d) → hard purge. Membro removido sai da audiência pendente.
4. Audience snapshot imutável: novos membros não recebem conteúdo anterior.

## 7. Media lifecycle (voz/vídeo)

- Mesh P2P (V1): WebRTC nativo (Electron) / react-native-webrtc (RN); host NÃO participa de
  media; JanjaNode coordena signaling (perfect negotiation via WebSocket).
- Guardrails iniciais (a medir): ~10 voz / ~6 câmeras; Simulcast p/ qualidade; DSCP se viável.
- Nenhuma gravação/transcrição; presence IN_CALL efêmera.
- Background mobile: iOS UIBackgroundModes=audio; Android FGS com tipo declarado (14+).

## 8. Host topology e replicação

- Single-writer (primary) + réplicas autorizadas warm-standby; lease TTL ~60–120s + fencing
  por epoch monotônico; op-log append-only (state machine replication sem consenso);
  snapshot periódico (SQLite VACUUM INTO/backup API).
- Durabilidade por classe: config/membership/crypto = 2-safe (ACK ≥1 réplica); mensagens/
  attachments/receipts = best-effort (efêmeros, perda tolerada).
- Failover: bully determinístico / arbitragem rendezvous; owner override (mobile); partition
  mode: message plane segue, membership/config sob gate (protege RFC 9420 §14).
- Rejeitados: Raft/Paxos (quórum indisponível em desktops), CRDT V1 (não resolve epochs MLS;
  tombstones vs purge).

## 9. Infra central (mínima)

- Rendezvous: records assinados (serverId = fingerprint host key), TTL curto, rate limits,
  DNS SRV/TXT bootstrap; nada de contas; lease/arbitragem de failover.
- STUN (RFC 8489) + TURN coturn (RFC 8656): REST credentials (timestamp+HMAC), portas
  3478/5349 + relay UDP 49152–65535; hardening (denied-peer-ip, quotas, TLS).
- Push: serviço central mínimo (FCM v1/APNs HTTP/2) — payload 100% estático
  ("New activity on JanjaCord"); tokens nunca expostos ao JanjaNode (capability tickets).
- Update: self-host assinado (Electron; macOS code-sign) / lojas (mobile).

## 10. Mobile constraints

- Expo dev builds (WebRTC/crypto exigem nativo; Expo Go não roda).
- react-native-webrtc 124.x (New Arch RN 0.76+; Android sólido, iOS validar em device).
- Secure storage: expo-secure-store (chaves pequenas); SQLite: expo-sqlite useSQLCipher.
- Push genérico opt-in; Android 13+ POST_NOTIFICATIONS em contexto.
- Visual ≈ desktop via design-tokens (não reutilizar componentes DOM).

## 11. Electron security boundaries

- contextIsolation + sandbox (defaults) mantidos; preload expõe o mínimo via contextBridge.
- Permissões de mídia via session.setPermissionRequestHandler (type media) +
  setPermissionCheckHandler; desktopCapturer só quando screen share entrar.
- safeStorage async no main (detectar backend basic_text no Linux); IPC com validação Zod.
- Sem Node no renderer; JanjaNode como módulo no main (ou processo filho isolado) quando host.

## 12. Dependências permitidas/proibidas

- Permitidas: mls-rs (WASM/UniFFI), Argon2id (node:crypto/quick-crypto/noble), SQLCipher,
  react-native-webrtc, node-datachannel, coturn, Zod, Zustand, TanStack Query, Tailwind,
  shadcn/ui, Expo (dev builds), NestJS, better-sqlite3-multiple-ciphers.
- Proibidas: qualquer SDK de analytics/tracking (PostHog/GA/Amplitude/Mixpanel/Firebase
  Analytics/Meta/Sentry user tracking); protocolo criptográfico próprio; libsignal como base
  de grupo (AGPL); keytar (arquivado); @journeyapps/sqlcipher (sem Windows); simple-peer
  (esconde renegociação, não roda RN).

## 13. Deployment model

- Desktop: installers por SO (5 SOs) + update self-host assinado.
- Mobile: lojas (Play closed testing / TestFlight) + dev builds.
- Infra central: containers (rendezvous, coturn, push) — self-hostable; docs em `infra/`.
- Nenhuma dependência de nuvem para conteúdo; custo central marginal ≪ volume de comunicação.

## 14. Failure modes

- Host offline → spool pendente; failover p/ réplica (janela lease+grace).
- TURN down → direct preferred degrada (fallback TURN público explícito) ou relay-only falha
  seguro.
- Rendezvous down → novas conexões/joins bloqueados; tráfego existente (Tailscale model) ok.
- Réplica divergente → catch-up por snapshot+log; partição residual → partition mode.
- Device perdido → recovery key; identidade sem recovery = perdida (por design).
- DS comprometido → pode DoS/delay/observar metadata; não lê conteúdo (E2EE).

## 15. Scale boundaries (V1)

- Mesh: ~10 voz / ~6 câmeras (guardrails a medir); server ~dezenas de membros; spool com
  quotas; central sem storage de conteúdo. SFU fora (SFrame avaliado pós-V1 se evidência).

## 16. Custo esperado (client vs server)

- Client: cifragem/decifragem, encode/decode media, storage local, banda P2P.
- Host: coordenação + ciphertext temporário (efêmero); replicas autorizadas.
- Central: rendezvous/STUN/TURN/push/update apenas (banda de relay é o custo maior documentado).
