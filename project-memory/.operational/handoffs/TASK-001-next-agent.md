# Handoff — One-shot concluído (próximo agente)

## Onde o projeto está

- **Fase:** Phase 8 (Release Hardening) — fases 0-7 concluídas em one-shot 2026-08-09.
  `completed_with_residual_risk` (SECURITY-REVIEW-001). Aguardando operator acceptance (M4 desta estação).
- **Repo:** `workspaces/janjacord/janjacord/` — 82 arquivos, commit inicial `f75879e`.
- **App testável:** desktop Electron Linux com E2EE real (MLS), server self-host, mensagens
  efêmeras + purge, attachments, mesh de call, QR device linking, relay-only.

## Evidência principal

- `artifacts/TASK-001/desktop-smoke/*.png` — screenshots do app real (login/home/server/mensagem E2EE)
- `reviews/OPERATOR-TEST-PACKET-RELEASE.md` — passos de teste do dono + blockers externos
- `reviews/SECURITY-REVIEW-001.md` — verdict + riscos residuais
- Bateria: 28 testes + 52 checks de smoke (janjanode 8, core 22, call 8, replica 11, relay 3)

## Como rodar (rápido)

```bash
cd workspaces/janjacord/janjacord
pnpm install && pnpm build
cd apps/desktop && node_modules/.bin/electron . --no-sandbox   # app interativo
node scripts/smoke-core.mjs   # M1 E2EE (sem display)
```

## Próximo passo exato

1. Dono: validar o app (packet) → approval M4 desta estação.
2. Blocker externo de maior valor: build mobile (`apps/mobile`, Expo) em host com Android SDK —
   exige react-native-webrtc dev build + UniFFI do mls-rs (spec group-crypto).
3. Deploy coturn + rendezvous (infra central) — arquitetura pronta (INTEGRATIONS/ADR-003).

## Não fazer

- NÃO reabrir decisões LOCKED (PRODUCT.md §2) sem conflito técnico documentado.
- NÃO usar libsignal como base de grupo (AGPL) nem protocolo criptográfico próprio.
- NÃO adicionar SDK de analytics/telemetria (auditoria é gate).
- NÃO tratar "scaffold" como entrega (todos os itens têm comportamento verificado).

## Riscos para o próximo agente

- mls-rs sem auditoria externa → orçar antes de release público (ADR-005)
- Broadcast de commit MLS entre 3+ membros (sync de commit — melhoria documentada)
- Replicação: lease automático como melhoria (ADR-011); fencing por epoch implementado
- WASM MLS roda no main do Electron (Node) — renderer via IPC (sandbox)
- STUN público pode ser bloqueado em redes restritas → coturn/TURN fallback
