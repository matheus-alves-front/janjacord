# SPEC — V1 Operator Acceptance Contract

## 1. Slice identity

- Slice / feature / artifact: contrato de aceite operacional da V1 (como o dono testa pessoalmente)
- Current phase: Phase 0-1 — definição (TASK-001)
- Target repo or artifact: `specs/` + `OPERATOR-TEST-PACKET-*` (futuros, por milestone)
- Product truth source: PRODUCT.md §7 (acceptance criteria), contrato congelado §69-§70
- Architecture truth source: ARCHITECTURE.md
- Checklist phase/item: milestones (MVP testável, alpha, beta, release)
- Primary actor / audience: dono do produto (operator)
- Final-user outcome: o dono valida comportamento real, não mock
- Why this matters now: build-to-user-test — testes automatizados são gates, não a entrega

## 2. Confirmed facts

- MVP testável (primeiro operator-testable milestone, LOCKED):
  Desktop A cria identidade → cria server self-hosted → gera invite → Desktop B cria identidade →
  entra pelo invite → ambos entram em #general → mensagem E2EE real enviada → recipient consome →
  lifecycle/purge funciona → nenhum plaintext existe no host spool.
  Sem fake data. Sem mock network. Sem "UI funcionando" com transporte falso.
- Segundo milestone natural: voz WebRTC real, direct mode, STUN, TURN fallback, call lifecycle,
  permissions; depois video, attachments, host replication, mobile, multi-device, relay-only,
  UX V1 completa. Ordem final definida pelo roadmap por risco/dependência.
- Cada milestone/subfase testável deve ter OPERATOR-TEST-PACKET com passos exatos, resultado
  esperado, limites conhecidos e rollback/cleanup.

## 3. Open decisions

- Nenhuma (milestones definidos pelo dono). Benchmarks de mesh (limites de call) alteram apenas
  guardrails, não milestones.

## 4. Real behavior contract

- Entry point: build/run real (desktop build ou dev run com transporte real).
- Main actions (MVP testável):
  1. Desktop A: cria identidade (nickname+senha) → recovery key visível uma vez.
  2. Desktop A: Create server → JanjaNode ativa → server visível no rail.
  3. Desktop A: gera invite (JC1-…) com expiração/limites default.
  4. Desktop B: cria identidade → Add server → cola invite → entra como Member.
  5. Ambos: #general → A envia mensagem → B recebe e lê (ciphertext nunca exposto).
  6. B sai do canal → mensagem some localmente; A consome também → purge.
  7. Inspeção: spool do host de A não contém plaintext (verificação via storage/inspeção).
- Data required: duas instâncias desktop reais no mesmo host ou rede; transporte real.
- Persistence or side effect: vault local, server state no host, envelopes temporários.
- Integrations/API calls: transporte real (DataChannel ou spool host real).
- Completion state: fluxo completo verificado pelo dono com checklist assinado.
- What must not be mocked: E2EE, transporte, purge, ausência de plaintext.

## 5. Required states and failures

- Loading: host inicializando; join aguardando sync.
- Empty: servidor sem membros ainda.
- Error: invite inválido; B sem rede.
- Invalid input: invite errado → erro claro.
- Unauthorized: B tenta canal privado sem permissão.
- Slow dependency: host de A offline → B não recebe pendências até A voltar.
- Partial failure: purge parcial durante queda — retoma quando host volta.
- Retry/recovery: A reinicia app → server volta; B reconecta e drena spool.

## 6. Acceptance criteria (MVP testável — o dono valida)

- [ ] Duas identidades criadas localmente sem email/telefone
- [ ] Server self-hosted em A; invite gerado com limites
- [ ] B entra pelo invite e aparece na member list
- [ ] Mensagem E2EE real trafega e é lida apenas por B
- [ ] Consumo + purge: mensagem some do host spool (verificação de storage)
- [ ] Nenhum plaintext observável no spool do host (inspeção)
- [ ] B que saiu do canal não vê mensagens consumidas ao voltar

## 7. Mock and placeholder policy

- Allowed only as internal draft: nada neste teste.
- Explicitly blocked for final: transporte fake, E2EE stub, purge simulado.
- Label required if mock remains: `MOCK`.
- Follow-up required before release: nenhum mock.

## 8. Client/public language gate

- Audience: dono do produto (interno).
- Terms that must not appear: n/a.
- Claims that require proof: "nenhum plaintext" — inspeção.
- Buyer/client language replacements: n/a.

## 9. (não aplicável)

## 10. Evidence required before checklist completion

- OPERATOR-TEST-PACKET-MVP assinado pelo dono (passos + resultado)
- Evidência de inspeção do spool (ausência de plaintext)
- Handoff registrado em `.operational/handoffs/`

## 11. Checklist projection

- Checklist file: CHECKLIST.md — milestone "MVP testável"
- Item(s): todos os itens do MVP
- Acceptance rule: `[x]` com operator packet assinado
- Evidence links: OPERATOR-TEST-PACKET; reviews

## 12. Source docs touched

- PRODUCT.md: sim
- ARCHITECTURE.md: sim (first slice)
- INTEGRATIONS.md: não
- ADR required: não
- Operator packet required: sim (este é o contrato)
