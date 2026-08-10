# SPEC — Message Consumption and Purge

## 1. Slice identity

- Slice / feature / artifact: semântica de consumo (RECEIVED→CONSUMED), ACK e purge global
- Current phase: Phase 0-1 — definição (TASK-001)
- Target repo or artifact: `specs/` + adr/ADR-004
- Product truth source: PRODUCT.md §5 (regras 1-3), contrato congelado §21-§26
- Architecture truth source: ARCHITECTURE.md (mensagem lifecycle; host spool; replicas)
- Checklist phase/item: fases de texto; purge/retention
- Primary actor / audience: host (coordena receipts), membros (consomem)
- Final-user outcome: mensagens não duram mais que o necessário; sem estado de leitura durável
- Why this matters now: purge define a promessa central de efemeridade e o custo de storage dos hosts

## 2. Confirmed facts

- Estados distintos: RECEIVED (entregue) → DELIVERED (disponível) → DECRYPTED → RENDERED →
  CONSUMED (apresentado ao usuário no canal ativo). Só RENDERED/CONSUMED conta como consumido.
- ACK de consumo é metadata temporária do protocolo; some junto com a mensagem.
- Usuário NÃO vê read receipts nem timestamps de leitura (LOCKED).
- Global purge: todos os destinatários ainda elegíveis consumiram → purge imediato
  (host ciphertext + replicas + delivery state + attachments associados + receipt state).
- Maximum retention: 1h/24h/7d/30d (default 7d); todo-mundo-consumiu vence antes; senão hard purge
  no TTL. Configurável pelo Owner (server/channel policy).
- Membro removido (kick/ban/perda de permissão) sai da audiência pendente; a mensagem não fica
  esperando ele. Ban bloqueia capacidade criptográfica futura.
- Sem tombstone identificável indefinido; se algum identificador anti-replay mínimo sobreviver,
  TTL justificado (ver spec networking).

## 3. Open decisions

- Granularidade do ACK (por mensagem vs lote; por device vs por identidade):
  - Why: custo de metadata vs latência de purge; multi-device (um usuário com 2 devices consumiu
    quando 1 consumiu?).
  - Options: (a) ACK por identidade (basta um device consumir); (b) ACK por device (todos os
    devices devem consumir). Recomendado: (a) por identidade com device opcional no envelope —
    simples, alinhado a "read once por pessoa"; múltiplos devices de um usuário dividem a mesma
    audiência lógica. Owner: architect + security. Blocking: sim (protocolo).
- Comportamento em canal não ativo no momento da entrega: mensagem fica pendente (DELIVERED)
  até ser apresentada ou expirar; ACK só na apresentação. (Regra fixa nesta spec.)
- App em background recebendo sem apresentar: permanece pendente (não consumida). Push genérico
  não conta como consumo.

## 4. Real behavior contract

- Entry point: envelope chega ao cliente (P2P ou spool host).
- Main actions:
  1. Cliente autentica e descriptografa; se canal não ativo, armazena ciphertext pendente localmente
     (efêmero, cifrado) e mantém `pending` no host.
  2. Canal ativo → renderiza → envia CONSUMED ACK (referência messageId + identity).
  3. Host marca recipient consumed; quando todos os elegíveis consumirem → dispara purge.
  4. Purge: remove ciphertext + attachments + delivery/consumption state no primary e replica;
     cliente local também purga o ciphertext pendente daquela mensagem.
  5. TTL: cron de retenção varre envelopes pendentes e purga os expirados (hard purge),
     incluindo receipt state.
- Data required: messageId, audience list, receipt state por mensagem, TTL policy.
- Persistence or side effect: estado de consumo temporário no host; nenhum histórico durável.
- Integrations/API calls: storage do host (spool), replicas (estado replicado), transporte.
- Completion state: mensagem e receipts inexistem em todos os nós JanjaCord.
- What must not be mocked: purge real (storage limpo), ACK real, TTL real.

## 5. Required states and failures

- Loading: spool grande no reconnect; drenagem ordenada por ordem de entrega.
- Empty: sem pendências; sem receipts.
- Error: ACK perdido → host reentrega/retenta até TTL.
- Invalid input: ACK de messageId desconhecido → ignorar (não criar estado).
- Unauthorized: ACK de identidade fora da audiência → rejeitar/ignorar.
- Slow dependency: host offline na entrega; purge atrasado até host voltar (TTL ainda conta).
- Partial failure: alguns ACKs chegam; purge só quando todos ou TTL.
- Retry/recovery: crash pós-render-pré-ACK → cliente re-ACK ao reconectar (idempotente);
  replica purgada também; reabrir canal não reapresenta consumidas.

## 6. Acceptance criteria

- [ ] Mensagem some imediatamente quando todos os elegíveis consumirem (inspeção de storage)
- [ ] Mensagem some no TTL mesmo com destinatário ausente (default 7d)
- [ ] Membro kickado/banido sai da audiência pendente sem segurar a mensagem
- [ ] ACK idempotente (duplicado não cria estado novo)
- [ ] Nenhum read receipt visível; nenhum timestamp de leitura persistido
- [ ] Reabrir canal não reapresenta mensagens consumidas
- [ ] Estado de consumo não sobrevive à mensagem (purge remove receipts)

## 7. Mock and placeholder policy

- Allowed only as internal draft: timers simulados em testes de TTL (não em operator test).
- Explicitly blocked for final: purge simulado, ACK falso, receipts persistidos.
- Label required if mock remains: `MOCK`.
- Follow-up required before release: nenhum.

## 8. Client/public language gate

- Terms that must not appear: "seen at", "read receipts", "engagement".
- Claims that require proof: "purge imediato" — inspeção de storage em operator test.
- Buyer/client language replacements: "consumed-then-purged", "retention-bounded".

## 9. (não aplicável)

## 10. Evidence required before checklist completion

- Teste de storage: ciphertext ausente após purge (host + replica)
- Teste de TTL: envelope expira com destinatário offline
- Operator-test: mensagem some ao sair/voltar ao canal

## 11. Checklist projection

- Checklist file: CHECKLIST.md — fase "Texto E2EE efêmero"
- Item(s): consumed semantics; global purge; maximum retention
- Acceptance rule: `[x]` com storage-verify de purge
- Evidence links: OPERATOR-TEST-PACKET; specs crypto/networking

## 12. Source docs touched

- PRODUCT.md: sim
- ARCHITECTURE.md: sim (lifecycle)
- INTEGRATIONS.md: não
- ADR required: ADR-004 (mesmo tema)
- Operator packet required: sim
