# SPEC — Ephemeral Read-Once Messaging (núcleo do produto)

## 1. Slice identity

- Slice / feature / artifact: semântica efêmera read-once de mensagens de texto
- Current phase: Phase 0-1 — definição (TASK-001)
- Target repo or artifact: `specs/` + `adr/ADR-004`
- Product truth source: PRODUCT.md §2 (Text), §5 (business rules 1-3), contrato congelado §16-§27
- Architecture truth source: ARCHITECTURE.md (mensagem lifecycle)
- Checklist phase/item: Phase 0 — spec da primeira fatia; fases de texto
- Primary actor / audience: membros de um server com permissão de canal
- Final-user outcome: conversa privada que desaparece quando consumida; sem histórico
- Why this matters now: é a característica mais distintiva do JanjaCord; define protocolo, host, purge

## 2. Confirmed facts

- Mensagem pertence à audiência autorizada no instante do envio (audience snapshot imutável).
- Novo membro NÃO recebe conteúdo anterior. Membro removido sai da audiência pendente.
- Consumo = autenticar + descriptografar + renderizar no canal ativo (não basta download).
- Enquanto o usuário permanece na sessão do canal, mensagens abertas continuam visíveis
  (evitar desaparecer na frente dos olhos).
- Ao sair do canal (ou app fechado, server trocado, background): plaintext local + attachments
  temporários destruídos; mensagens já consumidas não reaparecem.
- Global purge: todos os destinatários elegíveis consumiram → purge imediato de host + replicas +
  receipt state. Senão max retention (default 7d; 1h/24h/7d/30d configuráveis) → hard purge.
- Receipts de consumo são metadata temporária do protocolo; nunca vira read analytics,
  nem read receipts visíveis, nem last seen.
- Efemeridade não é DRM: cópias exportadas (copy/save/share/screenshot/gravação) estão fora do
  controle do produto.

## 3. Open decisions

- Representação exata do audience snapshot (lista de member IDs vs commitment criptográfico):
  - Why: define tamanho do envelope, privacidade de metadata, e comportamento sob mudança de membership.
  - Options: (a) lista explícita de device keys; (b) commitment/hash + lista de endpoints do host;
    (c) MLS group state snapshot. Recomendado: delegar à spec `group-crypto-and-key-lifecycle` +
    research MLS; baseline: host mantém lista de endpoints elegíveis + commitment criptográfico.
  - Owner: development-solution-architect + security-engineer (gate).
  - Blocking: sim — afeta wire protocol e envelope.
- Consumo ACK exato (quem ACK, quando, com que frequência): ver `message-consumption-and-purge.md`.
- Reabertura de canal em sessão nova: confirmado que mensagens consumidas NÃO reaparecem
  (LOCKED). Detalhe: o que acontece com mensagens recebidas mas NÃO consumidas (channel ativo
  mas não visualizado)? Regra: contam como pendentes até serem apresentadas ou expirarem.

## 4. Real behavior contract

- Entry point: membro com `view_channel` + `send_messages` no canal de texto.
- Main actions:
  1. Envio: autor calcula audiência atual → cifra (E2EE grupo, ver spec crypto) → cria
     `MessageEnvelope` (protocolVersion, messageId, serverId, channelId, sender identity ref,
     epoch/context crypto, audience commitment, ciphertext, attachment refs, ordering/replay
     protection, expiry) → entrega P2P (online) + spool cifrado host (offline).
  2. Recepção: recebe → autentica → descriptografa → renderiza no canal ativo → CONSUMED ACK.
  3. Consumo: visível enquanto a sessão do canal durar; destruição local ao sair do contexto.
  4. Purge: all-consumed → host+replicas+receipts purgados; senão retention → hard purge.
- Data required: identidade do remetente, member keys do canal, endpoint list do host, relógio/epoch.
- Persistence or side effect: ciphertext temporário no host/replicas; nada permanente.
- Integrations/API calls: transporte (DataChannel P2P / spool host), MLS/crypto adapter, storage local.
- Completion state: envelope e receipts não existem mais em nenhum nó JanjaCord.
- What must not be mocked: cifragem real, entrega real, consumo real, purge real.

## 5. Required states and failures

- Loading: mensagens pendentes no reconnect; spool sendo drenado.
- Empty: canal sem mensagens; audiência vazia (sem membros elegíveis — não enviar).
- Error: falha de descriptografia (epoch desatualizada) — não renderizar lixo; pedir estado atual.
- Invalid input: envelope com messageId duplicado (replay) — rejeitar.
- Unauthorized: destinatário fora da audiência não recebe; host não descriptografa.
- Slow dependency: host offline (entrega via P2P); P2P indisponível (spool).
- Partial failure: alguns ACKs chegam, outros não; purge espera até todos consumirem ou TTL.
- Retry/recovery: app crash antes do ACK → mensagem permanece pendente; reabrir canal não
  reapresenta consumidas; mensagens não consumidas continuam pendentes até expirar.

## 6. Acceptance criteria

- [ ] Mensagem é visível apenas para a audiência do instante do envio (novo membro não recebe)
- [ ] Consumo exige apresentação ao usuário no canal ativo (não apenas download)
- [ ] Ao sair do canal, plaintext local e attachments temporários são destruídos
- [ ] Reabrir o canal não reapresenta mensagens já consumidas
- [ ] Todos consumiram → mensagem some de host e replicas (verificável por inspeção do spool)
- [ ] Max retention (default 7d) força hard purge mesmo com destinatário ausente
- [ ] Receipts não geram analytics nem read receipts visíveis
- [ ] Replay de envelope é rejeitado (messageId/order unique)

## 7. Mock and placeholder policy

- Allowed only as internal draft: simulação de rede em testes unitários (NÃO em operator test).
- Explicitly blocked for final: E2EE mock, purge fake, plaintext no host.
- Label required if mock remains: `MOCK`.
- Follow-up required before release: remover qualquer simulação de transporte.

## 8. Client/public language gate

- Audience: open-source/auditores.
- Terms that must not appear: "leitura após envio" como métrica; "engajamento".
- Claims that require proof: "nenhum plaintext no host" — threat model + testes de spool.
- Buyer/client language replacements: "ephemeral by design", "audience-scoped", "purged after consumption".

## 9. (não aplicável)

## 10. Evidence required before checklist completion

- Testes de protocolo (envelope, audiência, replay)
- Teste de purge em host real (inspeção de storage)
- Operator-test: dois desktops, mensagem some após consumo

## 11. Checklist projection

- Checklist file: CHECKLIST.md — fase "Texto E2EE efêmero"
- Item(s): envelope; entrega; consumo; purge; retention
- Acceptance rule: `[x]` com operator-test de read-once verde
- Evidence links: specs de crypto/networking; OPERATOR-TEST-PACKET

## 12. Source docs touched

- PRODUCT.md: sim (já reflete esta spec)
- ARCHITECTURE.md: sim (message lifecycle)
- INTEGRATIONS.md: não
- ADR required: sim — ADR-004 (ephemeral read-once)
- Operator packet required: sim (MVP testável)
