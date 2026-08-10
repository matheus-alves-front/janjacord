# SPEC — Host Failure, Recovery and Replication Continuity

## 1. Slice identity

- Slice / feature / artifact: comportamento sob falha de host — recovery, failover, reconciliação
- Current phase: Phase 0-1 — definição (TASK-001)
- Target repo or artifact: `specs/` + `apps/janjanode` (futuro)
- Product truth source: PRODUCT.md §2 (Servers), contrato congelado §5, §7
- Architecture truth source: ARCHITECTURE.md (host topology; failure modes)
- Checklist phase/item: Phase 5 — Replicas
- Primary actor / audience: hosts, owner, membros
- Final-user outcome: falha de host quase invisível; nenhum estado irreversível quebrado
- Why this matters now: o modelo de replicação só vale se recovery/failover forem especificados

## 2. Confirmed facts (pesquisa 2026-08-09 — ReplicationScout)

- **Failover:** lease TTL ~60–120s (heartbeat para réplicas + rendezvous) → expiração → réplicas
  online reivindicam (bully determinístico: menor host ID; arbitragem via rendezvous
  sequence|ephemeral quando alcançável); owner pode forçar promoção/demissão (mobile +
  rendezvous). Promoção automática ativa message plane imediatamente; membership/config plane
  em partition mode (gate do owner ou 2-de-N) até ambiguidade resolver (RFC 9420 §14).
- **Recovery:**
  - Host ausente voltou: descarta estado local (standby nunca escreveu) e re-sincroniza do primary.
  - Primary original pós-promoção: não reivindica (epoch menor), vira standby; owner pode
    re-promover.
  - Réplica perdida: reprovisionada por snapshot (VACUUM INTO / Online Backup API) + op-log.
- **Split-brain residual** (partição total sem testemunha — FLP): aceito com blast radius
  pequeno — mensagens efêmeras dedup por messageId; config reconciliável por LWW-por-epoch
  com histórico de ops.
- **Consistência aceitável:** perda de mensagens efêmeras tolerada; ordem por sender +
  anti-replay (não global); durabilidade obrigatória só para memberships/config/crypto.
- Replicação de config/membership/crypto = ACK síncrono de ≥1 réplica (2-safe); mensagens =
  best-effort.

## 3. Open decisions

- Janela exata de grace period pós-lease (trade-off: latência de failover vs risco de
  reivindicação indevida). Recomendado: lease 60–120s + grace; calibrar com teste real.
- Nível de automação da promoção (semi vs automática): recomendado semi-automática por default
  (owner confirma quando alcançável; automática só se owner ausente > janela configurável).
- O que o cliente mostra quando o server está em partition mode (badge claro; reads ok,
  writes de membership pausados).

## 4. Real behavior contract

- Entry point: host detecta perda de primary (heartbeat/lease expirou) OU host volta ao ar.
- Main actions:
  1. Primary cai: heartbeat para → lease expira → réplicas reivindicam (ordem determinística,
     arbitragem rendezvous se alcançável); fencing token incrementa (epoch).
  2. Promovida ativa message plane (spool/entrega continua) e sinaliza partition mode para
     membership/config se a posse não estiver inequívoca.
  3. Owner (mobile/outro device) confirma/sobrescreve promoção quando necessário.
  4. Primary original volta: detecta epoch menor → vira standby → re-sincroniza.
  5. Host ausente volta: descarta estado local → snapshot + op-log catch-up → vira standby.
  6. Réplica perdida: reprovisionada por snapshot.
- Data required: lease/epoch, op-log, snapshots, heartbeat.
- Persistence or side effect: estado do server consistente após recovery; nenhum dado
  irreversivelmente perdido nas classes duráveis.
- Integrations/API calls: rendezvous (arbitragem, mapeamento hostID→endereço), transporte.
- Completion state: um primary inequívoco; membros reconectados; sem Commits MLS conflitantes.
- What must not be mocked: falha real (kill), failover real, reconciliação real.

## 5. Required states and failures

- Loading: catch-up (snapshot + log) — membros veem "server sincronizando".
- Empty: sem réplicas → server offline até primary voltar (UX clara, sem perda de dados
  duráveis — mas sem continuidade).
- Error: empate de reivindicação → arbitragem rendezvous/tie-break determinístico.
- Invalid input: n/a.
- Unauthorized: host não autorizado tenta reivindicar → rejeitado (denylist de réplicas).
- Slow dependency: rendezvous inalcançável na partição → partition mode + gate do owner.
- Partial failure: réplica promovida sem ter todo o log → catch-up antes de aceitar 2-safe
  de config (backfill).
- Retry/recovery: primary original vira standby; reconciliação por LWW-por-epoch quando
  necessário.

## 6. Acceptance criteria

- [ ] Kill do primary → réplica promovida → membros reconectam sem ação manual (janela ≤ lease+grace)
- [ ] Primary original volta sem reivindicar; vira standby consistente
- [ ] Membership/config/crypto não são perdidos em nenhuma falha de host único
- [ ] Partição residual não gera Commits MLS conflitantes (gate no membership plane)
- [ ] Mensagens efêmeras podem se perder sem quebrar o estado durável (documentado)
- [ ] Owner pode forçar promoção/demissão via mobile
- [ ] Réplica reprovisionada por snapshot fica consistente (verificação por epoch/seq)

## 7. Mock and placeholder policy

- Allowed only as internal draft: simulação de partição em testes.
- Explicitly blocked for final: failover simulado em operator test.
- Label required if mock remains: `MOCK`.
- Follow-up required before release: teste de falha real em rede local + WAN.

## 8. Client/public language gate

- Terms that must not appear: "epoch", "lease", "fencing" na UI.
- Claims that require proof: "server continua" — operator test de falha real.
- Buyer/client language replacements: "continuidade automática", "réplicas autorizadas".

## 9. (não aplicável)

## 10. Evidence required before checklist completion

- Teste de falha real (kill primary; failover; reconexão)
- Teste de recovery (primary volta; standby volta; reprovisionamento)
- Teste de partição (gate membership; mensagens continuam)
- Operator-test: desligar PC do owner, ver server continuar

## 11. Checklist projection

- Checklist file: CHECKLIST.md — Phase 5
- Item(s): failover, recovery, partition mode, reprovisioning
- Acceptance rule: `[x]` com teste de falha real
- Evidence links: QA-REVIEW; OPERATOR-TEST-PACKET

## 12. Source docs touched

- PRODUCT.md: sim
- ARCHITECTURE.md: sim (failure modes)
- INTEGRATIONS.md: sim (rendezvous)
- ADR required: ADR (host replication) cobre failover
- Operator packet required: sim
