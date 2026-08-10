# SPEC — Privacy, Metadata and Telemetry Policy

## 1. Slice identity

- Slice / feature / artifact: política de privacidade/metadata/telemetria — propriedade arquitetural
- Current phase: Phase 0-1 — definição (TASK-001)
- Target repo or artifact: `specs/` + adr/ADR-008 + threat-model (docs/)
- Product truth source: PRODUCT.md §2 (Privacy), §5 (regras 6-7, 11), contrato congelado §36, §52, §59-§60
- Architecture truth source: ARCHITECTURE.md (observability; infra central)
- Checklist phase/item: todas as fases (gate transversal)
- Primary actor / audience: todos (usuários, operadores, auditores)
- Final-user outcome: ausência de observabilidade comportamental; metadata mínima justificada
- Why this matters now: é o que diferencia o produto; precisa ser desenhada, não prometida

## 2. Confirmed facts

- **Zero user observability.** Proibidos remotamente: Google Analytics, PostHog, Amplitude,
  Mixpanel, Sentry user tracking, Meta SDK, Firebase Analytics, session replay, read analytics,
  engagement analytics, call analytics, message logs, content logs, social graph tracking,
  user behavior database, request-history product database, durable IP database.
- Serviços públicos JanjaCord: access logs desabilitados onde operacionalmente possível; sem
  histórico durável de requisições; sem storage de comportamento.
- Debugging: local, explicitamente habilitado, curto-lived, sanitizado. Crash report: opt-in
  manual; nunca envio automático com contexto privado.
- Presence: ONLINE/OFFLINE/IN_CALL apenas; efêmera; sem last seen/activity history/rich presence.
- Sem typing indicator; sem read receipts visíveis; ACK de consumo é interno e temporário.
- Distinção explícita: user observability = proibida; minimal infrastructure health (ex.: STUN/
  TURN/rendezvous operando) = permitida apenas se estritamente necessária para operar, documentada.
- Não prometer: anonimato matemático, invisibilidade de rede, zero metadata em qualquer componente,
  proteção contra endpoint/device comprometido, contra screenshot, contra export deliberado.
- Promessa: content-private, pseudonymous, metadata-minimizing, self-hostable, auditable.

## 3. Open decisions

- Exato mínimo de metadata do rendezvous (token de host, endpoints, timestamps efêmeros):
  - Why: rendezvous precisa de algo para encaminhar peers; minimizar e justificar.
  - Options: (a) apenas serverId/hostId + endpoint anunciado (efêmero); (b) + presença online do host;
    (c) + hash de nicknames (não). Recomendado: (a) + presença mínima de host para delivery;
    documentar TTLs. Owner: architect + security. Blocking: sim (protocolo) — ver spec rendezvous.
- Health checks agregados da infra central: se existirem, definir exatamente o que é coletado,
  agregado, retido, e quem acessa. Recomendado: contadores agregados de operação (ex.: tráfego
  TURN) sem identificador de usuário; documentar. Owner: platform. Blocking: não para V1 core.

## 4. Real behavior contract

- Entry point: qualquer execução do produto (desktop/mobile/host/rendezvous).
- Main actions:
  1. Nenhum SDK de analytics/tracking é linkado em runtime de produção.
  2. Logs locais: off por padrão; debug mode explícito; conteúdo sanitizado (sem plaintext de
     mensagens); rotação curta; export manual.
  3. Crash reporting: off por padrão; export manual opt-in (arquivo local); sem contexto
     automático.
  4. Infra central: sem logs de acesso persistentes; se health agregado existir, agregado e
     documentado.
  5. Presença: efêmera; expira com a sessão; nunca persiste histórico.
  6. Push: genérico; sem conteúdo/sender/server/channel no payload (ver spec mobile).
- Data required: mínimo necessário à função (endpoints, tokens efêmeros, estado de delivery).
- Persistence or side effect: nada de comportamento; metadata de protocolo apenas enquanto
  necessária, com TTL.
- Integrations/API calls: push (APNs/FCM — documentar trust boundary), stores, update.
- Completion state: produto operável sem coletar comportamento de usuário.
- What must not be mocked: ausência de SDKs é verificável no build (dependências); debug mode
  real; crash export real.

## 5. Required states and failures

- Loading: nada coletado durante boot.
- Empty: sem eventos.
- Error: falha não gera envio automático (apenas log local em debug mode).
- Invalid input: n/a.
- Unauthorized: n/a (não há coleta).
- Slow dependency: health agregado não deve correlacionar com identidade.
- Partial failure: se debug mode ligado por engano, sanear.
- Retry/recovery: opt-in de crash export re-pede permissão a cada export.

## 6. Acceptance criteria

- [ ] `package.json`/lockfile de produção não contém SDK de analytics/tracking
- [ ] Nenhuma chamada de rede para domínios de analytics em runtime normal
- [ ] Logs locais só gravam em debug mode explícito; sem plaintext de conteúdo
- [ ] Crash report é manual/opt-in; sem contexto automático
- [ ] Presença não persiste histórico; expira com a sessão
- [ ] Push payload não contém conteúdo/sender/server/channel
- [ ] Threat model público lista exatamente o que é e o que não é garantido

## 7. Mock and placeholder policy

- Allowed only as internal draft: n/a.
- Explicitly blocked for final: "telemetria minimalista", "analytics anônimos", qualquer SDK.
- Label required if mock remains: n/a.
- Follow-up required before release: auditoria de dependências.

## 8. Client/public language gate

- Audience: público/open-source.
- Terms that must not appear: "impossível de rastrear", "100% privado", "zero metadata".
- Claims that require proof: content privacy, metadata minimization (threat model + código).
- Buyer/client language replacements: "no product telemetry", "ephemeral", "self-hostable",
  "auditable", "content-private", "pseudonymous", "metadata-minimizing".

## 9. (não aplicável)

## 10. Evidence required before checklist completion

- Auditoria de dependências (nenhum SDK de tracking)
- Revisão de rede (nenhuma chamada a domínios de analytics)
- Threat model documentado e revisado por security engineer

## 11. Checklist projection

- Checklist file: CHECKLIST.md — gate transversal (todas as fases)
- Item(s): auditoria de telemetria; threat model; debug mode
- Acceptance rule: `[x]` com auditoria de dependências + review de segurança
- Evidence links: SECURITY-REVIEW; threat-model/docs

## 12. Source docs touched

- PRODUCT.md: sim
- ARCHITECTURE.md: sim (observability)
- INTEGRATIONS.md: sim (APNs/FCM/update)
- ADR required: ADR-008 (no durable behavioral telemetry)
- Operator packet required: sim (auditoria de privacidade)
