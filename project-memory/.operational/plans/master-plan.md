# Master Plan — JanjaCord (V1)

> Plano operacional de alto nível. Verdade durável de produto/arquitetura em `.progress/`.
> Fase atual: Phase 0-1 — Definição (TASK-001). Roadmap executável: `CHECKLIST.md`.

## Contexto

JanjaCord: comunicador privado de comunidades, invite-only, desktop+mobile, E2EE, efêmero,
user-hosted (JanjaNode), infra central mínima. Decisões de produto LOCKED (contrato 2026-08-09).
Esta operação (TASK-001) entrega Product → Specs → Architecture → UI/UX → Roadmap, SEM código.

## Milestones

| Milestone | Critério | Gate de saída |
|---|---|---|
| M0 Arquitetura/Specs prontas | PRODUCT + ARCHITECTURE + specs + ADRs + roadmap coerentes | approval do dono do roadmap |
| M1 MVP testável técnico | 2 desktops, identidade + server self-host + invite + E2EE real + consume + purge + sem plaintext no host | OPERATOR-TEST-PACKET-MVP assinado |
| M2 V1 alpha | texto completo + presence + invites + roles/permissions + replicas mínimas | operator packet alpha |
| M3 V1 beta | voz + vídeo mesh + attachments + multi-device + push genérico | operator packet beta |
| M4 V1 release | V1 completa nos 5 SOs | code review + QA + security + operator packets |

## Ordem por risco/dependência (não por facilidade)

1. **Protocolo + crypto adapter primeiro** (risco central: E2EE de grupo real, wire protocol,
   identidade) — sem isso nada é JanjaCord.
2. **MVP text real** (M1) — valida o núcleo efêmero read-once com transporte real.
3. **Voz/vídeo mesh** — segundo risco central (WebRTC, NAT, mesh limits).
4. **Attachments, replicação, mobile, multi-device, relay-only, UX completa** — em seguida.

## Fases do roadmap (detalhe em CHECKLIST.md)

- Phase 0 — Definição (esta operação)
- Phase 1 — Foundation: monorepo, domain/protocol/crypto adapters, identidade local, vault, testes
- Phase 2 — Server/hosting/membership/invites/permissions (JanjaNode mínimo)
- Phase 3 — MVP text E2EE efêmero (M1): envelope, entrega P2P+spool, consume, purge, retention
- Phase 4 — Realtime/voice/video (M3 parcial): mesh WebRTC, STUN/TURN, call lifecycle
- Phase 5 — Attachments + presença + replicação/failover (M2/M3)
- Phase 6 — Multi-device + push genérico + mobile (M3)
- Phase 7 — Relay-only, self-host TURN, polimento V1 (M4)
- Phase 8 — Release hardening: code review, QA, security review, threat model final

## Especialistas por fase

- Phase 1-3: development-solution-architect, development-backend-engineer, development-security-engineer (gate), development-frontend-engineer (UI mínima), development-qa-release-engineer (gates)
- Phase 4: development-backend-engineer (signaling), development-frontend-engineer/mobile (WebRTC), design-ui-ux-designer (call UX)
- Phase 5-6: development-backend-engineer, development-mobile-engineer, development-platform-devops-engineer (push), development-security-engineer
- Phase 7-8: todos + development-code-reviewer, development-qa-release-engineer

## Riscos técnicos principais

1. MLS cross-platform (FFI em RN + Node): ver ADR-005 + research MlsScout. Fallback: libsignal ou
   primitivas padrão com justificativa.
2. WebRTC em React Native (manutenção da lib, background, permissões): ver research WebRtcScout.
3. Mesh scalability: guardrails ~10 voz / ~6 câmeras a medir; SFU fora de V1.
4. Replicação/failover sem infra central confiável (split-brain): ver research ReplicationScout.
5. Secure storage multiplataforma (vault): Keychain/Keystore size limits; KDF para senha.
6. Push central sem vazar conteúdo (payload estático; tokens isolados do JanjaNode).
7. Wire protocol versioning + replay protection + ordering: definido antes de código.
8. Relay-only enforcement real (sem candidates diretos).

## Hipóteses não comprovadas

- [ ] Limites de mesh (10 voz / 6 câmeras) — precisam de benchmark real
- [ ] MLS em RN via FFI é viável com maturidade suficiente (2026)
- [ ] Spool + purge alcança "sem plaintext no host" em todas as condições de falha
- [ ] Rendezvous mínimo sustenta N hosts sem metadata durável
- [ ] UX de read-once é compreensível sem frustração (teste com usuário)

## Primeira task executável futura

TASK-002 (proposta): **Wire protocol v0 + crypto adapter boundary** — definir envelope,
identity hierarchy, MLS adapter interface, schema Zod, testes de protocolo. Só após approval do
roadmap (esta operação) e da spec da primeira fatia.

## Restrições

- Nenhum código antes de M0 aprovado e da primeira spec operator-testable
- Nada fora de `workspaces/janjacord/janjacord/`
- Sem protocolo criptográfico próprio; sem SDK de telemetria
