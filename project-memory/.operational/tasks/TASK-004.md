# TASK-004 — JanjaNode mínimo: hosting, membership, invites, permissions (proposta — aguardando approval)

## Routing stamp

- execution_mode: heavy-task (implementation slice) — BLOQUEADA até M0 aprovado
- workflow: development-execucao-segura-de-tarefa
- primary_owner: development-backend-engineer (NestJS)
- supporting_specialists: development-security-engineer (gate — invites/permissions),
  development-solution-architect (módulos/ports-adapters)
- required_gates: security review de invites/membership/permission evaluation
- target_repo: workspaces/janjacord/janjacord/
- evidence_required_before_done: testes de precedência/limites/replay; operator-test (2 clientes, 1 server)
- stop_conditions: sem transporte E2EE real ainda (vem na TASK-005); sem UI completa

## Objetivo

JanjaNode (NestJS modular) hospedando server localmente: membership, roles/permissions
(flags + precedência + channel overrides), invites capability (assinatura do owner), kick/ban
por identidade, ownership transfer, presence efêmera, estado persistido em SQLite cifrado.

## Escopo

1. `apps/janjanode`: módulos identity/server/membership/roles/channels/invites/permissions/
   presence/hosting (modular + ports/adapters nas fronteiras trust-sensitive).
2. `packages/domain`: entidades + regras (server, channel, membership, invite, role, ban).
3. `packages/permissions`: avaliação com precedência documentada (deny canal > allow role >
   server default; owner override) — suite de testes.
4. `packages/schemas`: Zod para comandos (create server, invite, join, kick, ban, override).
5. Persistência: SQLite cifrado (raw key) para server state; op-log append-only preparado
   para replicação (ADR-011).
6. Testes: precedência, limites/expiração/revogação de invite, replay, ban × invite,
   ownership transfer.

## Aceite

- Dois clientes gerenciam o mesmo server via host real (join por invite, roles, overrides).
- Testes de precedência/permissão/ban/invite verdes; security review fechado.
- Estado durável sobrevive a restart do host (sem perda de membership/config).

## Notas

- Depende: TASK-002 (protocolo), TASK-003 (identidade), specs `server-hosting-and-replication.md`,
  `invite-membership-protocol.md`, `roles-and-channel-permissions.md`, ADR-002/011.
- Replicação/failover completos ficam na fase de replicas (não nesta task inicial).
