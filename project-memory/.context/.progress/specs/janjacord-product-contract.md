# SPEC — JanjaCord Product Contract (contrato executável de produto)

## 1. Slice identity

- Slice / feature / artifact: contrato executável de produto JanjaCord (V1)
- Current phase: Phase 0-1 — definição (TASK-001)
- Target repo or artifact: `.progress/PRODUCT.md` + esta spec
- Product truth source: contrato congelado 2026-08-09 (TASK-001)
- Architecture truth source: `ARCHITECTURE.md` (a consolidar nesta operação)
- Integration truth source: `INTEGRATIONS.md`
- Checklist phase/item: Phase 0 — Product truth em PRODUCT.md
- Primary actor / audience: dono do produto, arquitetos, implementadores futuros
- Final-user outcome: produto impossível de ser mal interpretado antes da implementação
- Why this matters now: nenhum código antes de contratos executáveis

## 2. Confirmed facts

- Produto: comunicador privado de comunidades, invite-only, desktop+mobile, só comunicação.
- Modelo mental LOCKED: Server → Channel → Text/Call. Frase: "Server. Channel. Talk. Nothing else."
- Identidade: nickname+senha; identidade criptográfica local; senha ≠ identidade; recovery key.
- Mensagens: E2EE, efêmeras, read-once, audience snapshot, purge, max retention (default 7d).
- Servers: user-hosted (JanjaNode no desktop), replicas autorizadas, failover simples.
- Infra central: mínima (rendezvous/STUN/TURN/update); nunca storage de conteúdo.
- Voz/vídeo: WebRTC mesh P2P V1; guardrails ~10 voz / ~6 câmeras (a medir).
- Privacy: zero analytics/telemetria; sem read receipts visíveis; sem typing indicator; push genérico.
- Plataformas: Windows/macOS/Linux (Electron); Android/iOS (RN/Expo).
- Decisões de produto: todas LOCKED — reabrir só com conflito técnico/material documentado.

## 3. Open decisions

- Nenhuma decisão de produto em aberto (LOCKED).
- Decisões técnicas (fora desta spec): MLS impl, hierarquia de chaves, vault, device linking,
  replicação, wire protocol, push backend, rendezvous → specs/ADRs/stack-docs.

## 4. Real behavior contract

- Entry point: primeira abertura → nickname + senha → Create identity (vault + keypair + recovery key).
- Main actions: create server; invite; join by key; text/call channel; read-once; purge; roles;
  permissions; kick/ban; ownership transfer; device linking; network privacy policy.
- Data required: identidade criptográfica local; estado do server no host; envelopes cifrados.
- Persistence or side effect: vault local cifrado; ciphertext temporário no host/replicas;
  nada durável na central.
- Integrations/API calls: WebRTC (DataChannel/media); STUN/TURN; rendezvous; push (APNs/FCM);
  secure storage nativo; KDF.
- Completion state: mensagem consumida por todos → purge total; ou max retention → hard purge.
- What must not be mocked: E2EE real, transporte real, purge real, ausência de plaintext no host
  (MVP testável: ver `v1-operator-acceptance-contract.md`).

## 5. Required states and failures

- Loading: primeira abertura, join, host inicializando.
- Empty: sem servers; canal vazio; server sem members.
- Error: invite inválido/expirado/revogado; permissão negada; host offline; TURN indisponível.
- Invalid input: senha fraca; invite malformado; nickname duplicado no server.
- Unauthorized: canal privado; banido; kickado; sem initial role.
- Slow dependency: STUN/TURN lento; rendezvous inacessível; replica atrasada.
- Partial failure: spool parcial; attachment interrompido; replica divergente.
- Retry/recovery: host reinicia; replica promovida; device perdido; recovery key; crash durante consumo.

## 6. Acceptance criteria

- [ ] Um implementador novo entende V1 completo lendo PRODUCT.md + specs sem ler chat
- [ ] Nenhuma regra da seção 5 (business rules) do PRODUCT.md admite duas interpretações materiais
- [ ] Toda feature V1 mapeia para ao menos uma spec com critério verificável
- [ ] Toda não-feature (out of scope) está listada como não-goal em PRODUCT.md
- [ ] O primeiro fluxo operator-testable (MVP) está definido sem fake data nem mock network

## 7. Mock and placeholder policy

- Allowed only as internal draft: mockups de UI em design exploration (fora de V1 release).
- Explicitly blocked for final: mock de E2EE, transporte, purge, permissões.
- Label required if mock remains: `MOCK` em superfície visível.
- Follow-up required before release: nenhum mock remanescente.

## 8. Client/public language gate

- Audience: comunidade técnica/open-source (futuro).
- Purpose: documentar produto para auditoria.
- Terms that must not appear: "impossível de rastrear", "100% anônimo", "zero metadata",
  linguagem de engajamento ("crescimento", "viralidade", "retenção").
- Claims that require proof: garantias criptográficas (content-private, pseudonymous,
  metadata-minimizing) com respaldo do threat model.
- Buyer/client language replacements: "content-private", "pseudonymous", "metadata-minimizing",
  "ephemeral", "self-hostable", "auditable protocol".

## 9. (não aplicável — sem superfície pública comercial)

## 10. Evidence required before checklist completion

- PRODUCT.md completo (done nesta operação)
- Specs 1-20 criadas com critérios verificáveis
- ADRs/ARCHITECTURE/INTEGRATIONS coerentes
- Operator-test packet para MVP testável

## 11. Checklist projection

- Checklist file: `CHECKLIST.md` — Phase 0 (Definição) e fases subsequentes
- Item(s): fechamento da Phase 0; abertura da primeira fatia executável
- Acceptance rule: `[x]` quando PRODUCT.md + specs + arquitetura estiverem coerentes e aprovados
- Evidence links: paths `.progress/` acima

## 12. Source docs touched

- PRODUCT.md: feito (reescrito nesta operação)
- ARCHITECTURE.md: sim (a escrever)
- INTEGRATIONS.md: sim (a escrever)
- ADR required: não (contrato de produto, não decisão arquitetural)
- Operator packet required: sim (MVP testável)
