# SPEC — Direct vs Relay Network Privacy Policy

## 1. Slice identity

- Slice / feature / artifact: políticas de privacidade de rede (direct preferred / relay only)
- Current phase: Phase 0-1 — definição (TASK-001)
- Target repo or artifact: `specs/` + adr/ADR-007 + `packages/networking` (futuro)
- Product truth source: PRODUCT.md §2 (Network privacy), contrato congelado §33-§35, §39-§40
- Architecture truth source: ARCHITECTURE.md (transport abstraction; TURN)
- Checklist phase/item: fases de networking/voice
- Primary actor / audience: Owner (configura policy do server), participantes
- Final-user outcome: política de rede explícita; nenhum modo prometido como "invisível"
- Why this matters now: é o ponto mais delicado — metadata de transporte existe em ambos os modos

## 2. Confirmed facts

- Dois modos (policy por server, escolhida pelo Owner):
  - **Direct preferred:** P2P quando possível; TURN fallback quando NAT impede. Menor latência e
    custo; maior exposição de metadata de rede entre peers.
  - **Relay only:** nunca expor rota direta entre peers; transporte passa pelo relay configurado.
    Reduz exposição de endereço direto; o relay observa metadata de transporte.
- NENHUM dos modos é "invisível para a internet": em conexões IP, algum metadado de transporte é
  observável por algum participante da rede. Isso está no threat model, não escondido.
- Conteúdo continua E2EE em ambos os modos (relay não acessa conteúdo).
- Self-hosted relay: server avançado pode rodar seu próprio TURN (JanjaNode + TURN); JanjaCord
  Inc. não entra no caminho. Fallback público JanjaCord: explicitamente visível, nunca silencioso.
- Configuração não precisa ser complexa: Owner escolhe uma de duas opções.

## 3. Open decisions

- Como o modo é sinalizado/negociado (server policy propagada aos clientes; TURN credentials):
  - Why: relay-only exige que o cliente NUNCA candidate rotas diretas (mais que "preferência").
  - Options: (a) policy no server state, clientes a aplicam localmente; (b) signaling controlado
    pelo host escolhe o relay. Recomendado: (a) + host/signaling só oferece candidatos
    compatíveis com a policy. Owner: architect + security. Blocking: sim (networking).
- Quem opera o relay em relay-only: server próprio vs fallback público explícito. V1: server pode
  configurar TURN; fallback público só com consentimento explícito do Owner (flag).
- Quando relay-only falha (relay indisponível): bloquear comunicação (falha segura) vs degradar
  para direct (viola policy)? Recomendado: falha segura com erro claro — policy é política.
  Owner: security. Blocking: sim (UX de erro + networking).

## 4. Real behavior contract

- Entry point: Owner configura Network Privacy no server (Direct preferred | Relay only).
- Main actions:
  1. Policy propagada com o estado do server.
  2. Join de call/DataChannel: coleta candidatos ICE conforme policy (direct: host+srflx+relay
     fallback; relay-only: apenas relay).
  3. Negociação via signaling; conexão estabelecida conforme policy.
  4. Se fallback público for usado, estado visível na UI (ex.: badge "relay público").
- Data required: policy, ICE candidates, TURN config, status do relay.
- Persistence or side effect: policy no server state (replicado); TURN credentials temporárias.
- Integrations/API calls: TURN server (coturn), signaling, ICE.
- Completion state: chamada/dados fluem com a política escolhida; violação bloqueada.
- What must not be mocked: relay-only real (sem candidatos diretos), falha segura real.

## 5. Required states and failures

- Loading: negociando.
- Empty: sem relay configurado em relay-only → join bloqueado com erro instrutivo.
- Error: relay caiu em relay-only → chamada termina com erro claro; direct preferred → fallback TURN.
- Invalid input: TURN mal configurado → aviso ao Owner.
- Unauthorized: n/a.
- Slow dependency: STUN lento; relay overloaded.
- Partial failure: um peer sem relay (relay-only) não entra na call.
- Retry/recovery: reconnect mantém a mesma policy.

## 6. Acceptance criteria

- [ ] Direct preferred usa P2P quando possível e TURN fallback quando necessário
- [ ] Relay only NUNCA troca media/dados por rota direta (verificação de candidates)
- [ ] Relay only sem relay disponível → falha segura com erro claro (sem degradar para direct)
- [ ] Fallback público JanjaCord é explicitamente visível na UI quando usado
- [ ] Conteúdo permanece cifrado nos dois modos (relay não acessa conteúdo)
- [ ] Configuração do Owner é simples (uma escolha binária + relay opcional)

## 7. Mock and placeholder policy

- Allowed only as internal draft: simulação de ICE em testes unitários.
- Explicitly blocked for final: relay-only que vaza candidatos diretos.
- Label required if mock remains: `MOCK`.
- Follow-up required before release: teste de candidates em relay-only.

## 8. Client/public language gate

- Terms that must not appear: "anonimato de rede", "impossível de rastrear".
- Claims that require proof: relay-only semantics — teste de candidates ICE.
- Buyer/client language replacements: "direct preferred", "relay only", "network privacy policy".

## 9. (não aplicável)

## 10. Evidence required before checklist completion

- Teste de candidates ICE (relay-only não emite host/srflx)
- Teste de falha segura (relay down em relay-only)
- Operator-test: configurar os dois modos e verificar comportamento

## 11. Checklist projection

- Checklist file: CHECKLIST.md — fases de networking/voice
- Item(s): direct preferred; relay only; self-host relay; fallback explícito
- Acceptance rule: `[x]` com teste de candidates + operator-test
- Evidence links: specs networking; QA-REVIEW

## 12. Source docs touched

- PRODUCT.md: sim
- ARCHITECTURE.md: sim (transport abstraction; TURN)
- INTEGRATIONS.md: sim (TURN/coturn)
- ADR required: ADR-007 (direct vs relay)
- Operator packet required: sim
