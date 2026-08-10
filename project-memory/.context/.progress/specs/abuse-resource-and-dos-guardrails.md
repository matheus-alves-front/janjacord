# SPEC — Abuse, Resource and DoS Guardrails

## 1. Slice identity

- Slice / feature / artifact: proteções contra abuso/exaustão de recursos sem tracking invasivo
- Current phase: Phase 0-1 — definição (TASK-001)
- Target repo or artifact: `specs/` + adr (protocolo) + docs/threat-model
- Product truth source: contrato congelado §60, PRODUCT.md §6 (edge cases)
- Architecture truth source: ARCHITECTURE.md (host limits; quotas; rate limits)
- Checklist phase/item: fases de protocolo, host, invites, media
- Primary actor / audience: hosts, rendezvous, invites, media
- Final-user outcome: privacidade sem deixar o produto trivialmente derrubável
- Why this matters now: limites precisam ser desenhados antes do protocolo (não adicionados depois)

## 2. Confirmed facts

- Privacidade não pode significar "sem proteção alguma contra abuso".
- Proteções NÃO podem depender de tracking invasivo (sem reputação comportamental central,
  sem fingerprinting, sem IP-based identity).
- Áreas a proteger: invites (brute force, replay, enumeration, leaked invites); handshake
  (rate limits); peers (resource caps por conexão); attachments (size limits, quotas, cleanup);
  malformed packets (rejeição); replay (proteção); voice/video (participant limits); spool
  (quotas de storage); replicas (quotas).
- Invites: backend/host deve evitar armazenar secret puro quando houver opção segura
  (hash/proof); analisar replay, brute force, enumeration, leaked invites.
- Voice/video V1: guardrails ~10 voz / ~6 câmeras (iniciais, a medir com benchmarks reais).

## 3. Open decisions

- Quotas exatas de spool/attachment (tamanho por arquivo, total por server, TTL):
  - Why: custo do host; DoS; UX.
  - Options: (a) limites fixos default (ex.: 50 MB/arquivo, 2 GB/server, TTL conforme retention);
    (b) configuráveis pelo owner; (c) ambos — defaults + configuração. Recomendado: (c) com
    defaults defensivos documentados; valores finais a calibrar em benchmarks.
  - Owner: architect + platform. Blocking: sim (media/host specs).
- Rate limits de handshake/rendezvous (requests/min por IP anônimo vs por token):
  - Why: proteger rendezvous sem coletar metadata durável.
  - Options: (a) token bucket por IP com TTL curto em memória; (b) proof-of-work leve em joins;
    (c) ambos. Recomendado: (a) para rendezvous/handshake + (b) opcional para invites
    (custo baixo, sem correlação durável). Owner: security + platform. Blocking: sim.
- Limites de participante em call: fixos vs dinâmicos: ver `voice-video-webrtc.md`.

## 4. Real behavior contract

- Entry point: qualquer ação que consuma recurso de host/rendezvous/rede.
- Main actions:
  1. Invite: chave com entropia suficiente; verificação por hash; rate limit de tentativas por
     origem; expiração/limites/revogação sempre verificados; replay de invite rejeitado.
  2. Handshake/join: rate limit; validação de formato; rejeição de malformed packets;
     handshake timeouts.
  3. Peers/conexões: caps por peer (conexões ativas, bandwidth); backoff em falha.
  4. Attachments: size limit por arquivo; chunking com retry; quotas por server; TTL alinhado
     à retention; cleanup automático.
  5. Voice/video: participant limits; recusa de join além do limite com erro claro.
  6. Spool: quotas de storage; expiração; cleanup.
- Data required: counters efêmeros em memória (não duráveis), quotas configuradas.
- Persistence or side effect: nenhuma reputação durável; nenhum fingerprinting.
- Integrations/API calls: storage, transporte, rendezvous.
- Completion state: abuso contido sem coletar comportamento durável.
- What must not be mocked: rate limits reais, size limits reais, quota real, cleanup real.

## 5. Required states and failures

- Loading: n/a.
- Empty: servidor sem recursos — limites default ativos.
- Error: limite atingido → erro claro ("tente mais tarde", "arquivo grande demais").
- Invalid input: invite malformado; chunk fora de ordem; packet malformado → rejeição silenciosa.
- Unauthorized: join além do limite de participantes.
- Slow dependency: rate limiter em memória perdido em restart (aceitável — efêmero).
- Partial failure: upload interrompido → retry idempotente; cleanup remove chunks órfãos.
- Retry/recovery: backoff exponencial no handshake.

## 6. Acceptance criteria

- [ ] Brute force de invite falha dentro de janela de rate limit
- [ ] Invite expirado/revogado/usado não funciona; replay de invite rejeitado
- [ ] Attachment acima do limite é recusado antes de consumir storage relevante
- [ ] Quota de spool impede exaustão de disco do host; cleanup roda no TTL
- [ ] Call rejeita join além do participant limit com erro claro
- [ ] Nenhum mecanismo acima persiste identidade comportamental durável
- [ ] Malformed packets não derrubam host/rendezvous (fuzz básico verde)

## 7. Mock and placeholder policy

- Allowed only as internal draft: n/a.
- Explicitly blocked for final: rate limit decorativo, quota sem cleanup.
- Label required if mock remains: `MOCK`.
- Follow-up required before release: fuzz básico de malformed packets.

## 8. Client/public language gate

- Terms that must not appear: "moderação por IA", "reputação".
- Claims that require proof: "limits sem tracking" — revisão de código.
- Buyer/client language replacements: "resource caps", "rate-limited", "storage quotas".

## 9. (não aplicável)

## 10. Evidence required before checklist completion

- Testes de rate limit/limites (automatizados)
- Fuzz básico de malformed packets
- Operator-test: limites configuráveis funcionando

## 11. Checklist projection

- Checklist file: CHECKLIST.md — fases de invites/media/host
- Item(s): invite guardrails; media limits; spool quotas; call limits
- Acceptance rule: `[x]` com testes de limites verdes
- Evidence links: QA-REVIEW; specs networking/media

## 12. Source docs touched

- PRODUCT.md: sim (edge cases)
- ARCHITECTURE.md: sim (limits/quotas)
- INTEGRATIONS.md: não
- ADR required: não isolado (entra em ADRs de protocolo/media)
- Operator packet required: sim (limites configuráveis)
