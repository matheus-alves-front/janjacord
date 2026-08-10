# SPEC — Server Hosting and Replication

## 1. Slice identity

- Slice / feature / artifact: modelo de hosting user-hosted + replicação entre hosts
- Current phase: Phase 0-1 — definição (TASK-001)
- Target repo or artifact: `specs/` + `apps/janjanode` + `packages/domain` (futuro)
- Product truth source: PRODUCT.md §2 (Servers; Host), contrato congelado §4-§7
- Architecture truth source: ARCHITECTURE.md (host topology; replication)
- Checklist phase/item: Phase 2 (JanjaNode), Phase 5 (replicas)
- Primary actor / audience: Owner (primary host), authorized replicas, membros
- Final-user outcome: server sobrevive ao desligamento do PC do owner; failover quase invisível
- Why this matters now: diferencia o produto (self-hosted) e é risco distribuído real

## 2. Confirmed facts (pesquisa 2026-08-09 — ReplicationScout)

- **Modelo recomendado: single-writer com lease + réplicas warm-standby assíncronas + fencing
  por epoch; failover semi-automático.**
- **DATA PLANE:** replicação assíncrona de op-log append-only (state machine replication SEM
  consenso; cada op com header epoch/seq/messageId) aplicada pelas réplicas; snapshot periódico
  (SQLite VACUUM INTO / Online Backup API) para provisionar réplica nova e catch-up.
- **Durabilidade por classe:**
  - config/memberships/roles/channels/invites/estado crypto = write com ACK síncrono de ≥1
    réplica (2-safe) → sobrevive à perda de qualquer host
  - ciphertext pendente/attachments/receipts = assíncrono best-effort (perda tolerada: domínio
    efêmero read-once)
- **CONTROL PLANE:** lease TTL ~60–120s renovado por heartbeat (réplicas + rendezvous);
  fencing token por epoch monotônico (clientes rejeitam servidor de epoch menor); promoção
  bully-style determinística (menor host ID) ou arbitrada pelo rendezvous (sequence|ephemeral);
  owner override via mobile.
- **SPLIT-BRAIN:** prevenção em camadas (fencing → testemunha → tie-break determinístico);
  caso residual (partição total, FLP) → partition mode: message plane prossegue (relay efêmero),
  membership/config plane (que gera Commits MLS) fica sob gate do owner/2-de-N até reconciliação
  (protege RFC 9420 §14: Commits conflitantes no mesmo epoch exigem resolução canônica).
- **RECOVERY:** standby que voltou descarta estado local e re-sincroniza (nunca escreveu);
  primary original pós-promoção não reivindica (epoch menor), vira standby; réplica perdida é
  reprovisionada por snapshot.
- **Rejeitados:** Raft/Paxos (quórum de maioria indisponível com desktops — server precisa
  funcionar com 1 host online); CRDT na V1 (não elimina single-writer de epochs MLS; tombstones
  conflitam com purge sem tombstone indefinido).
- [INFERENCE] Chave de identidade do server deve ser replicada às réplicas para promoção
  preservar identidade — decisão a confirmar na arquitetura (ADR).
- Dependência: failover exige que o rendezvous atualize mapeamento hostID→endereço (acoplar
  com `rendezvous-nat-stun-turn.md`).

## 3. Open decisions

- Número default de réplicas recomendado (2) e como owner autoriza; quotas por réplica.
- Promoção automática vs semi-automática: recomendado semi-automática com owner override
  (não surpreender usuário comum); mensagem plane ativa imediatamente.
- Epoch/fencing: formato exato do token e onde é verificado (host, clientes) — arquitetura.

## 4. Real behavior contract

- Entry point: Owner cria server → vira Primary Host (JanjaNode ativo no desktop).
- Main actions:
  1. Primary grava mutações no SQLite cifrado local → op-log append-only.
  2. Ops de config/membership/crypto: ACK síncrono de ≥1 réplica (2-safe) antes de responder.
  3. Ops de mensagem/attachment/receipts: assíncrono best-effort.
  4. Réplicas autorizadas (owner aprova) aplicam op-log; snapshot periódico para catch-up.
  5. Heartbeat renova lease; expiração → réplicas reivindicam (bully/rendezvous); fencing
     rejeita escritas de epoch antigo.
  6. Partition mode (se necessário): mensagens continuam; membership/config sob gate.
- Data required: op-log, epochs, lease, snapshots, réplica authorization.
- Persistence or side effect: SQLite cifrado em cada host; op-log; snapshots periódicos.
- Integrations/API calls: rendezvous (lease/arbitragem/mapeamento), transporte (replicação).
- Completion state: server operacional com continuidade quando primary cai.
- What must not be mocked: replicação real (2 hosts), lease real, fencing real.

## 5. Required states and failures

- Loading: catch-up de réplica nova (snapshot + log).
- Empty: sem réplicas — server roda só no primary (perda tolerada no desligamento).
- Error: lease expirou sem réplica → server offline até primary voltar (ou owner promove).
- Invalid input: n/a.
- Unauthorized: réplica não autorizada tenta replicar → rejeitada.
- Slow dependency: réplica lenta no ACK 2-safe → timeout com retry; mensagens seguem best-effort.
- Partial failure: partição (réplica inalcançável) → 2-safe degrada para best-effort com aviso
  ao owner; reconciliação na volta.
- Retry/recovery: standby re-sincroniza; primary original não reivindica; snapshot reprovisiona.

## 6. Acceptance criteria

- [ ] Server continua operacional quando o primary desliga, com réplica promovida
- [ ] Membership/config/crypto sobrevivem à perda de qualquer host (ACK 2-safe)
- [ ] Mensagens efêmeras podem ser perdidas sem quebrar crypto epochs (documentado)
- [ ] Fencing rejeita escritas de epoch antigo (split-brain prevenido no plano de dados)
- [ ] Partição residual não gera Commits MLS conflitantes (gate no membership plane)
- [ ] Owner pode promover/demitir réplicas e forçar override
- [ ] Réplica perdida é reprovisionada por snapshot sem divergência

## 7. Mock and placeholder policy

- Allowed only as internal draft: simulação de partição em testes.
- Explicitly blocked for final: failover fake, replicação simulada em operator test.
- Label required if mock remains: `MOCK`.
- Follow-up required before release: teste de falha real (kill primary).

## 8. Client/public language gate

- Terms that must not appear: "single-writer", "fencing", "epoch" na UI.
- Claims that require proof: "server continua sem o PC do owner" — operator test.
- Buyer/client language replacements: "seu server continua online com réplicas autorizadas".

## 9. (não aplicável)

## 10. Evidence required before checklist completion

- Teste de falha: primary kill → réplica promovida → server operacional
- Teste de fencing/epoch (escrita de epoch antigo rejeitada)
- Teste de ACK 2-safe (membership sobrevive à perda de host)
- Operator-test: 2 hosts, desligar o primary

## 11. Checklist projection

- Checklist file: CHECKLIST.md — Phase 2, Phase 5
- Item(s): JanjaNode hosting, replicas, lease, failover, partition mode
- Acceptance rule: `[x]` com teste de falha real
- Evidence links: QA-REVIEW; OPERATOR-TEST-PACKET

## 12. Source docs touched

- PRODUCT.md: sim
- ARCHITECTURE.md: sim (host topology; replication)
- INTEGRATIONS.md: sim (rendezvous)
- ADR required: ADR (host replication) + ADR (user-hosted server model)
- Operator packet required: sim
