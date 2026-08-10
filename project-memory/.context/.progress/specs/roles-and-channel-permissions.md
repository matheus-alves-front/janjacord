# SPEC — Roles and Channel Permissions

## 1. Slice identity

- Slice / feature / artifact: roles, hierarquia, permission flags e channel overrides
- Current phase: Phase 0-1 — definição (TASK-001)
- Target repo or artifact: `specs/` + `packages/permissions` (futuro)
- Product truth source: PRODUCT.md §2 (Roles & permissions), contrato congelado §40-§43
- Architecture truth source: ARCHITECTURE.md (permissions domain)
- Checklist phase/item: fases de server/membership
- Primary actor / audience: Owner, Admins, Moderators, Members
- Final-user outcome: autorização testável por flags, não por `if role === "admin"`
- Why this matters now: private channels e overrides dependem de precedência definida

## 2. Confirmed facts

- Defaults: Owner 100, Admin 80, Moderator 50, Member 10. Custom roles permitidos.
- Flags obrigatórias V1:
  - SERVER: manage_server, manage_channels, manage_roles, manage_invites
  - MEMBERS: kick_members, ban_members, assign_roles
  - TEXT: view_channel, send_messages, send_files
  - CALL: join_call, speak, enable_camera, mute_members, remove_from_call
- Canal pode sobrescrever permissões (ex.: #staff — Admin view yes, Moderator view yes, Member no).
- Kick: remove agora; pode voltar com novo convite (salvo outra policy).
- Ban: adiciona identidade criptográfica à denylist do server; convite posterior não permite
  reentrada da mesma identidade; ban não usa email/telefone/IP/hardware fingerprint.
- Precedência de avaliação precisa ser definida e testável (role base → multiple roles →
  channel allow/deny → owner override).
- Ownership transfer existe (confirmação, autoridade criptográfica, impacto em hosts).

## 3. Open decisions

- Modelo exato de avaliação (allow/deny por canal vs net effect por role):
  - Why: private channels + multiple roles + overrides podem conflitar.
  - Options: (a) additive: maior level vence, deny explícito vence allow; (b) allowlist por canal
    (nega por padrão, roles listados ganham); (c) híbrido com deny explícito soberano.
    Recomendado: (b) para `view_channel` em canais privados (default deny) + (a) para demais
    flags, com deny explícito de canal vencendo allow de role; Owner sempre override.
    Owner: architect + security (gate — avaliação de permissão é trust boundary).
  - Blocking: sim (permissions package + protocolo).
- Hierarchy: level numérico simples vs DAG de roles: V1 usa level numérico (simples, suficiente).
- Custom roles: herança? V1: sem herança; só nível + flags. Blocking: não.

## 4. Real behavior contract

- Entry point: membro executa ação (ver canal, enviar, entrar em call, kickar, banir, criar invite).
- Main actions:
  1. Ação mapeada para flag (ex.: enviar → `send_messages`).
  2. Avaliação: server default flags da role → channel override (allow/deny) → owner override.
  3. Decisão: allow/deny com erro claro quando negado.
  4. Kick: remove membership imediato; não afeta identidade criptográfica global.
  5. Ban: adiciona denylist do server; join por invite com mesma identidade → rejeitado.
  6. Ownership transfer: confirmação explícita; hosts/replicas atualizados; falha no meio
     → estado consistente (sem owner duplo nem sem owner).
- Data required: role assignments, channel overrides, hierarchy, denylist, owner identity.
- Persistence or side effect: estado de roles/permissions no host (replicado); denylist no server.
- Integrations/API calls: membership protocol, host state, invites (initial role).
- Completion state: decisão de permissão consistente entre host e clientes.
- What must not be mocked: avaliação de permissão real no servidor/host (não só UI).

## 5. Required states and failures

- Loading: permissões ainda sincronizando (client usa cache local validado).
- Empty: server sem roles custom — defaults ativos.
- Error: permissão negada → tela de erro com ação sugerida (pedir acesso).
- Invalid input: role inexistente no assign.
- Unauthorized: member sem `view_channel` em canal privado.
- Slow dependency: host offline na avaliação de kick/ban (filas de intenção? V1: host é autoridade —
  se offline, ação adiada com feedback).
- Partial failure: ban aplicado mas replica atrasada — reconciliação.
- Retry/recovery: denylist replicada; ownership transfer interrompido → rollback/retry com
  confirmação.

## 6. Acceptance criteria

- [ ] Ação negada por flag correta em canal público e privado
- [ ] Channel override deny vence role allow (teste de precedência)
- [ ] Owner não pode ser rebaixado; ownership transfer só com confirmação
- [ ] Kickado pode reentrar com novo invite; banido (mesma identidade) não
- [ ] Avaliação de permissão roda no host (não apenas escondida na UI)
- [ ] Custom role com flags específicas funciona (ex.: Moderator sem `ban_members`)
- [ ] Precedência documentada e testada: deny canal > allow role > server default

## 7. Mock and placeholder policy

- Allowed only as internal draft: UI mock de settings de permissão.
- Explicitly blocked for final: avaliação de permissão no client apenas (deve ser validada no host).
- Label required if mock remains: `MOCK`.
- Follow-up required before release: testes de precedência.

## 8. Client/public language gate

- Terms that must not appear: "admin power", "mod tools" (linguagem de produto final: "roles and permissions").
- Claims that require proof: precedência — suite de testes.
- Buyer/client language replacements: "permission flags", "channel overrides", "role hierarchy".

## 9. (não aplicável)

## 10. Evidence required before checklist completion

- Suite de testes de precedência (allow/deny/owner)
- Teste de ban por identidade (reentrada bloqueada)
- Operator-test: criar role custom, aplicar override, verificar acesso

## 11. Checklist projection

- Checklist file: CHECKLIST.md — fase "Server & Membership"
- Item(s): roles defaults, custom roles, flags, overrides, kick, ban, ownership transfer
- Acceptance rule: `[x]` com testes de precedência + operator-test
- Evidence links: QA-REVIEW; specs invites/membership

## 12. Source docs touched

- PRODUCT.md: sim
- ARCHITECTURE.md: sim (permissions domain)
- INTEGRATIONS.md: não
- ADR required: não isolado (decisão de precedência documentada em ARCHITECTURE; possível ADR se
  houver trade-off material)
- Operator packet required: sim
