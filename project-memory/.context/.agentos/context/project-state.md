# Project State — janjacord

## Estado atual (2026-08-09, definicao congelada)

- Produto: **JanjaCord** — comunicador privado de comunidades, invite-only, desktop + mobile.
  Foco exclusivo em comunicacao: Server → Channel → Text/Voice/Video. Nada de rede social.
- Fase: definicao congelada entregue pelo usuario (contrato 2026-08-09); TASK-001 em execucao
  (Product → Specs → Architecture → UI/UX → Roadmap). Implementacao (Phase 5) NAO iniciada.
- Repo alvo: `workspaces/janjacord/janjacord/` (registrado no router; NAO criado).
- Stack baseline (a validar): monorepo pnpm+Turborepo; Electron+React+Vite+Tailwind+shadcn/ui
  (desktop); React Native+Expo (mobile); NestJS/Node (JanjaNode); WebRTC/DataChannel/ICE/STUN/TURN;
  E2EE de grupo via protocolo padrao (MLS candidato); SQLite local encryptado; Zod; Zustand;
  TanStack Query; Vitest/Playwright.
- Contexto da memoria seed: **reclassificado template->stale e substituido** — os artefatos
  originais ("versao simplificada do Discord com peculiaridades a definir") contradiziam a
  definicao congelada e foram reescritos nesta operacao.

## Verdade duravel em `.progress/`

- PRODUCT.md (reescrito nesta operacao), ARCHITECTURE.md (reescrito), INTEGRATIONS.md (reescrito),
  CHECKLIST.md (phase-roadmap reescrito), specs/ (contratos), adr/ (decisoes).
- specs/: 20 specs obrigatorias do contrato (agrupamento final pode consolidar).
- adr/: ~16 ADRs (identidade, hosting, infra central, read-once, MLS, mesh, relay, telemetria,
  Electron/RN, shadcn, attachments, versioning, monorepo).

## Decisoes fechadas (nao reabrir sem conflito tecnico material documentado)

Ver TASK-001 / briefing: sem email/telefone; identidade pseudonima criptografica local;
servers user-hosted (JanjaNode); infra central minima (rendezvous/STUN/TURN/update);
mensagens efemeras read-once com audience snapshot e purge; E2EE padrao (nao proprio);
WebRTC mesh V1 (voice ~10, video ~6 como guardrail inicial, a medir); direct preferred /
relay only; sem analytics/telemetria; Electron desktop + React Native mobile; shadcn design
language; V1 sem DMs/discovery/threads/forums/stickers/webhooks/bots/SFU.

## Pendente

- Research tecnica (MLS impl, WebRTC RN/Electron, secure storage, replication/failover,
  push generico, protocolo/rendezvous) -> specs/ADRs/ARCHITECTURE.
- UI/UX contracts desktop + mobile.
- CHECKLIST.md phase-roadmap, master-plan, primeira wave de TASKs.
- Approval do roadmap antes de qualquer implementacao.
