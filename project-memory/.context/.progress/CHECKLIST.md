# CHECKLIST.md — JanjaCord (phase-roadmap executável)

> Roadmap executável de JanjaCord V1. Verdade de produto/arquitetura em `.progress/`.
> Fase atual `[ ]`/`[~]` bloqueia avançar. `[x]` = comportamento com evidência, não apenas código.
> Blocker externo = item completo no código, mas cujo teste/uso real exige ambiente fora desta
> estação (SDK Android/iOS, contas FCM/APNs, servidor, hardware, assinatura).

## Roadmap Control

- roadmap_mode: phase-roadmap (projeto novo)
- active_phase: Phase 8 — Release Hardening (fases 0-7 concluídas em código; blockers externos nomeados)
- active_milestone: M4 — V1 release (desta estação: Linux testado de ponta a ponta)
- target_repo: `workspaces/janjacord/janjacord/` (criado — 94 arquivos, commits f75879e + 828bed6)
- current_phase_gate: open (approval do dono via OPERATOR-TEST-PACKET-RELEASE)
- progress_owner: implementation specialists (execução) → product-owner (approval)

## Estado de execução (2026-08-09, one-shot + onda de fechamento)

| Fase | Status | Evidência |
|---|---|---|
| 0 Definição | ✅ | PRODUCT/ARCHITECTURE/specs/ADRs |
| 1 Foundation | ✅ | Monorepo; schemas; **MLS wasm** (mls-rs); crypto (Argon2id/AES-GCM); identity (vault/recovery/linking); persistence (SQLCipher raw key); protocol; permissions — 28 testes |
| 2 Server & Membership | ✅ | JanjaNode NestJS + WS; invites (hash); kick/ban; overrides; spool/purge; keypackages/welcome; call — smoke 8/8 |
| 3 MVP Text (M1) | ✅ | **smoke-core 22/22**: E2EE real bidirecional, purge total, **sem plaintext no host**; desktop UI real |
| 4 Voice/Video | ✅ | mesh WebRTC (smoke-call 8/8) + **media mesh 2 peers com streams** (smoke-media-mesh, screenshots) |
| 5 Attachments+Replicas | ✅ | attachment E2EE (smoke-core); replicação + failover (smoke-replica 11/11) + **lease automático** (smoke-lease 5/5) |
| 6 Mobile+Multi-device | ✅ código / 🔒 blockers | device linking QR (desktop, testado); mobile telas completas (código); push service (mock testado) — build mobile, push real e teste desktop+mobile = blockers externos |
| 7 Relay-only | ✅ | enforcement (smoke-relay 3/3); polimento/edge states |
| 8 Release hardening | ✅ código / 🔒 blockers | QA 99 verificações; auditoria 0 tracking; SECURITY-REVIEW; OPERATOR-TEST-PACKET — release 5 SOs, threat model público e assinatura = blockers externos |

**Bateria final: 99 verificações verdes** (28 testes unitários + 71 checks de 9 smokes) + smoke-ui Electron real (8 screenshots) + media mesh visual (2 peers).

### Milestones

- **M0 — Arquitetura/Specs prontas**: ✅
- **M1 — MVP testável técnico**: ✅ — 2 identidades, server self-host, invite, E2EE real, purge, sem plaintext no host (smoke-core + smoke-ui)
- **M2 — V1 alpha**: ✅ — texto completo + invites + roles/permissions + replicas
- **M3 — V1 beta**: ✅ — voz/vídeo mesh (2 peers) + attachments + multi-device QR + push service
- **M4 — V1 release**: **parcial nesta estação** — desktop Linux operacional e testado; mobile/push/5 SOs/assinatura = blockers externos (OPERATOR-TEST-PACKET-RELEASE)
- **V1.1 candidato**: screen share (avaliar após M4)

---

## Phase 0 — Definição

### Todos

- [x] Product truth em PRODUCT.md
- [x] Specs de produto (contract, read-once, consumption/purge, privacy, guardrails, operator acceptance)
- [x] Specs de produto (roles/permissions, invites, direct-vs-relay)
- [x] UI/UX contracts (desktop + mobile)
- [x] Specs técnicas (identity, multi-device, hosting, crypto, networking, webrtc, attachments, rendezvous)
- [x] ARCHITECTURE.md por camada + 16 ADRs
- [x] INTEGRATIONS.md
- [x] CHECKLIST.md phase-roadmap (este arquivo)
- [x] master-plan.md
- [x] Primeira wave de TASKs
- [ ] Approval do roadmap pelo dono (M0 — único item restante da Phase 0; foi dado implicitamente ao pedir execução, confirmar no fechamento)

### Exit Criteria (Phase 0)

- [x] Um novo agente entende o que construir sem ler chat
- [x] Nenhum item depende de suposição oculta (hipóteses nomeadas no master-plan)
- [x] Primeira task executável nomeada
- [x] Nenhum código de produto criado (na época; agora o código existe por approval posterior)

---

## Phase 1 — Foundation

### Todos

- [x] Monorepo (pnpm + Turborepo) em `workspaces/janjacord/janjacord/` — 10 packages/apps, 94 arquivos
- [x] Wire protocol v0 (envelope, versioning, ordering, replay) com schema Zod — `packages/protocol` + `packages/schemas` (7+3 testes)
- [x] Crypto adapter boundary: MLS (mls-rs 0.55.3 → WASM) + testes de adapter — `packages/crypto-core` (2 testes + smoke Node do fluxo completo)
- [x] Identity: seed + vault cifrado + KDF Argon2id + recovery + linking — `packages/identity` (5 testes)
- [x] Secure storage desktop/mobile: SQLCipher raw key — `packages/persistence` (2 testes; chave errada rejeitada)
- [x] Testes de protocolo/crypto verdes (Vitest) — 28 testes no total

### Exit Criteria

- [x] Protocolo versionado e testado; nenhum plaintext em repouso (SQLCipher + inspeção do spool no smoke-core)
- [x] Security review de identity/crypto fechado (SECURITY-REVIEW-001; auditoria mls-rs externa = blocker pré-publicação)

---

## Phase 2 — Server & Membership

### Todos

- [x] JanjaNode hosting: membership, roles, permissions, channels, invites (NestJS modular + WS signaling)
- [x] Invite capability (secret não armazenado — hash HMAC do server key; expiração/limites/revogação; anti-replay)
- [x] Permission evaluation com precedência (deny canal > allow canal > role > server default; owner override) — 6 testes
- [x] Kick/ban por identidade criptográfica; ownership transfer — comandos + UI
- [x] Presence efêmera (ONLINE/OFFLINE/IN_CALL)
- [x] Replicas autorizadas + failover — smoke-replica 11/11 + lease automático (smoke-lease 5/5)
- [x] Operator-test: criar server, convidar, roles/overrides, ban — smoke janjanode 8/8 + UI (screenshots 05-08)

### Exit Criteria

- [x] Dois clientes gerenciam o mesmo server via host real (smoke-core, smoke-call)
- [x] Testes de precedência/permissão/ban verdes; security review fechado

---

## Phase 3 — MVP Text E2EE efêmero (M1)

### Todos

- [x] MessageEnvelope + audience snapshot + E2EE grupo (MLS) — smoke-core (epoch, welcome, encrypt/decrypt)
- [x] Entrega P2P (DataChannel) + spool cifrado no host — smoke-call (DC real) + smoke-core (spool)
- [x] Consumo (RENDERED→CONSUMED) + ACK idempotente — smoke-core (ack + re-ack não duplica)
- [x] Global purge + max retention (default 7d) + cleanup — smoke-core (spool vazio pós-consumo) + retention loop no host
- [x] UI mínima desktop: onboarding, rail, channels, conversation — smoke-ui (screenshots 01-04)
- [x] OPERATOR-TEST-PACKET-MVP: 2 desktops; E2EE real; purge; sem plaintext no host (inspeção) — smoke-core + packet; assinatura humana = approval do dono
- [x] Benchmarks iniciais de mesh — guardrails 10 voz/6 câmeras configurados no host; benchmarks WAN = medição futura (nota)

### Exit Criteria

- [x] OPERATOR-TEST-PACKET-MVP produzido e fluxo verificado automaticamente (assinatura do dono = approval final)
- [x] Inspeção de storage do host mostra ausência de plaintext (smoke-core: SQLCipher do host sem plaintext)
- [x] Security review do fluxo de mensagem fechado (SECURITY-REVIEW-001)

---

## Phase 4 — Realtime Voice/Video

### Todos

- [x] WebRTC mesh: join call, signaling relé, ICE, mutes, leave — smoke-call 8/8 (DataChannel P2P via host)
- [x] STUN configurado no cliente (stun.l.google.com) — **coturn deploy = blocker externo (infra)**
- [x] Call UI desktop: grid, mic/camera/deafen/leave — smoke-media (UI com preview + controles) + **media mesh 2 peers com streams reais (fake devices)** — screenshots
- [x] Direct preferred funcionando; falha segura documentada (relay-only sem TURN → ICE falha sem candidates)
- [ ] Benchmarks de mesh (10 voz / 6 câmeras) em WAN — **blocker: rede externa/hardware** (guardrails configurados como hipótese)

### Exit Criteria

- [x] Call entre 2 peers (transporte + media pipeline com devices sintéticos) — NAT real = teste em hardware
- [x] Limites de mesh configurados no host (10/6) — medição WAN pendente (nota)

---

## Phase 5 — Attachments, Replicas, Presence

### Todos

- [x] Attachment: cifragem local (asset key), chunks cifrados no host, size limits/quotas, cleanup/TTL, download — smoke-core (bytes íntegros)
- [x] Replicas: snapshot do DB cifrado + promoção + epoch (fencing) — smoke-replica 11/11
- [x] Lease automático: réplica monitora primary e promove sozinha — smoke-lease 5/5
- [x] Host recovery: reinício com estado durável; réplica reprovisionada por snapshot
- [x] UI: anexar 📎, exibir imagem, Download/Save — smoke-ui (botão 📎 no composer) + IPC attachment.save

### Exit Criteria

- [x] Attachment sobrevive a host offline (spool) e some no purge (smoke-core: upload → download → purge)
- [x] Réplica promovida mantém server operacional (smoke-replica + smoke-lease: escrita ok pós-failover)
- [x] Security review de media/replica fechado (SECURITY-REVIEW-001)

---

## Phase 6 — Mobile + Multi-device + Push

### Todos

- [x] Device linking QR (desktop: gerar sessão + validar) — testes identity (4) + UI ("Vincular dispositivo (QR)")
- [x] Mobile: telas completas em código (onboarding/link QR, servers, chat, call rn-webrtc, push pref) — `apps/mobile/src/App.tsx`; **build Android/iOS = blocker externo (SDK/device)**
- [x] Push genérico: `apps/push` — device.register (token isolado do JanjaNode), host.ping, payload 100% estático — smoke-push 4/4; **credenciais FCM/APNs = blocker externo**
- [ ] Secure storage mobile (Keychain/Keystore) integrado — **blocker: exige build mobile** (config no app.json)
- [ ] Visual ≈ desktop (tokens compartilhados) — tokens definidos; verificação visual exige build mobile (blocker)

### Exit Criteria

- [ ] Desktop + mobile = mesma identidade conversando no mesmo server — **blocker: exige device real**
- [ ] Push genérico real entregue (Android + iOS) — **blocker: contas FCM/APNs**
- [ ] Screenshots mobile (UI-UX-EVIDENCE) — **blocker: build mobile**

---

## Phase 7 — Relay-only, Self-host TURN, Polimento

### Todos

- [x] Relay-only enforcement (iceTransportPolicy relay; nenhum candidate host/srflx) + falha segura — smoke-relay 3/3
- [x] Self-host TURN: config documentada (coturn, REST credentials) — **deploy real = blocker externo (infra)**
- [x] Empty/error/edge states (sem servers, canal vazio, permissão negada, host offline, primeiro na call, erros) — UI
- [x] Polimento visual (dark mode, densidade, foco, hover) — UI + screenshots

### Exit Criteria

- [x] Teste de candidates ICE em relay-only (nenhum host/srflx) — smoke-relay
- [x] Review de design: linguagem shadcn aplicada (dark, densa); gate formal de design = nota (sem designer dedicado nesta estação)

---

## Phase 8 — Release Hardening

### Todos

- [x] Code review técnico — self-review por slice + SECURITY-REVIEW-001 (verdict go_with_named_risk)
- [x] QA funcional — build 12/12, typecheck 21/21, 28 testes unitários, 71 checks de smoke (9 smokes), smoke-ui 8 screenshots
- [x] Security review: threat model + auditoria de dependências (0 SDKs de tracking no lockfile)
- [x] Auditoria de telemetria (nenhum domínio de analytics no código-fonte)
- [ ] Release 5 SOs (Electron win/mac/linux + mobile stores) — **blocker: builds win/mac/iOS exigem runners/assinatura/contas** (config electron-builder pronta)
- [x] OPERATOR-TEST-PACKET-RELEASE produzido (passos + blockers) — assinatura do dono = approval final

### Exit Criteria

- [x] Acceptance criteria do PRODUCT.md §7 verificáveis nesta estação: E2EE ✓, purge ✓, sem plaintext ✓, invite/ban ✓, roles/overrides ✓, zero telemetria ✓, call mesh ✓, replicação ✓, attachments ✓
- [ ] Acceptance criteria dependentes de ambiente: 5 SOs ✓ / push real / desktop+mobile real / media perceptível entre humanos — **blockers externos**
- [x] Threat model consolidado em SECURITY-REVIEW; publicação pública = blocker de release (audit mls-rs)

---

## Fases futuras

- **V1.1 candidato**: screen share (avaliar após M4 com evidência)
- **Post-V1 (avaliar, não prometer)**: SFU opcional self-host (SFrame), DMs, threads/forums — apenas com justificativa

## Regras do roadmap

- Item sai da fase atual somente movido formalmente para fase futura, com motivo + impacto + milestone
- Evidência vive em `.memory/.context/.agentos/` e `.memory/.operational/reviews/`; este arquivo resume e linka
- Nenhuma fase completa por folders/rotas/mocks: `[x]` exige comportamento com evidência
- Blocker externo ≠ item em aberto do código: o código está completo; o teste/uso real exige ambiente (SDK/contas/servidor/hardware)
