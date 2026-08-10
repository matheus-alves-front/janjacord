# SPEC — Invite and Membership Protocol

## 1. Slice identity

- Slice / feature / artifact: convites (capabilities) e entrada em servers
- Current phase: Phase 0-1 — definição (TASK-001)
- Target repo or artifact: `specs/` + `packages/protocol` + `packages/domain` (futuro)
- Product truth source: PRODUCT.md §2 (Invites, Servers), contrato congelado §13
- Architecture truth source: ARCHITECTURE.md (membership; invites)
- Checklist phase/item: fase "Server & Membership"
- Primary actor / audience: Owner/Admin (cria), novos membros (usam)
- Final-user outcome: entrar em server somente por capability; sem discovery
- Why this matters now: entrada é o único caminho para servidores — precisa de anti-abuso e
  revogação real

## 2. Confirmed facts

- Dois fluxos: Create server; Add server (invite key).
- Invite = capability com secret único, formato exemplo `JC1-XXXX-...`.
- Parâmetros V1: expiration; maxUses; initialRole; revoke. Exemplos: 1 use / 10 uses / unlimited;
  1h / 1 day / 7 days / no expiry.
- Revogar invite invalida novas entradas.
- Backend/host deve evitar armazenar secret puro quando houver opção segura (hash/proof);
  analisar replay, brute force, enumeration, leaked invites.
- Sem busca de servers; sem trending; sem suggested.
- Nickname é server-specific; a autoridade é a identidade criptográfica.

## 3. Open decisions

- Representação do invite (secret assinado vs hash no host):
  - Why: se o host armazena o secret, um host comprometido pode convidar arbitrariamente;
    hash evita isso, mas exige verificação de proof.
  - Options: (a) invite = assinatura do owner sobre claims (sem secret no host, verificação por
    chave pública do owner); (b) hash do secret no host (verificação por hash, owner mantém
    segredo); (c) híbrido. Recomendado: (a) assinatura do owner — permite revogação por
    `inviteId` + nonce, sem secret armazenado; verificar replay via nonce único.
    Owner: security-engineer (gate). Blocking: sim (protocolo).
- Entropia do secret/forma de codificação (base32? UUIDv4?): mínimo 128 bits, base32 com
  checksum para UX. Owner: architect. Blocking: não.
- Enrollment de membership (quem autoriza a entrada efetiva): owner/admin com manage_invites
  pode criar; entrada aplica initialRole. Membership final efetivada pelo host (autoridade).
- Leaked invite (distribuição fora de controle): revoke é a resposta; maxUses limita dano.

## 4. Real behavior contract

- Entry point: Owner/Admin com `manage_invites` abre Create invite.
- Main actions:
  1. Criar invite: claims (serverId, role inicial, expiração, maxUses, inviteId, nonce) →
     assinatura do owner → secret codificado apresentado ao usuário.
  2. Compartilhar: fora de banda (copy/share).
  3. Usar: novo usuário cola key → host valida (assinatura, expiração, usos, revogação,
     denylist de ban) → cria membership com initialRole → membro entra.
  4. Revogar: owner/admin revoga inviteId → novos usos rejeitados.
  5. Uso registrado: contador de usos (sem histórico de quem usou além do necessário ao
     membership — metadata mínima).
- Data required: chave pública do owner, claims, nonce, contador de usos, denylist.
- Persistence or side effect: registro de invites ativos/revogados no host (replicado);
  membership persistido (server state).
- Integrations/API calls: membership protocol, permissions (initialRole), host state.
- Completion state: membro com role inicial; invite consumido/revogado corretamente.
- What must not be mocked: validação de assinatura/expiração/limites/ban no host.

## 5. Required states and failures

- Loading: validação em andamento.
- Empty: nenhum invite criado ainda.
- Error: invite inválido/expirado/revogado/esgotado/banido → erro claro e distinto.
- Invalid input: key malformada → erro imediato.
- Unauthorized: usar invite sem assinatura válida; criar invite sem manage_invites.
- Slow dependency: host offline (join aguarda host).
- Partial failure: uso registrado mas membership não confirmado → idempotência (nonce reusado
  não duplica membership).
- Retry/recovery: nonce replay rejeitado; revoked invite em cache local é limpo.

## 6. Acceptance criteria

- [ ] Invite com maxUses=1 funciona uma vez e depois rejeita
- [ ] Invite expirado é rejeitado; revogado é rejeitado imediatamente
- [ ] Entrada aplica initialRole corretamente
- [ ] Identidade banida não entra nem com invite novo válido (denylist)
- [ ] Host não armazena secret puro (verificação por assinatura/hash)
- [ ] Replay de invite (mesmo nonce duas vezes) não duplica membership
- [ ] Sem busca/descoberta de servers (nenhum endpoint de discovery)

## 7. Mock and placeholder policy

- Allowed only as internal draft: n/a.
- Explicitly blocked for final: invite sem validação real, membership fake.
- Label required if mock remains: `MOCK`.
- Follow-up required before release: testes de replay/brute force.

## 8. Client/public language gate

- Terms that must not appear: "código de acesso genérico" (é capability por identidade).
- Claims that require proof: revogação e limites — testes.
- Buyer/client language replacements: "invite-only", "revocable invites", "usage-limited".

## 9. (não aplicável)

## 10. Evidence required before checklist completion

- Testes de expiração/limites/revogação/replay
- Teste de ban × invite (reentrada bloqueada)
- Operator-test: criar invite, usar, revogar, tentar usar de novo

## 11. Checklist projection

- Checklist file: CHECKLIST.md — fase "Server & Membership"
- Item(s): invite keys, expiry, limits, revoke, initial role
- Acceptance rule: `[x]` com testes de validação + operator-test
- Evidence links: specs membership; QA-REVIEW

## 12. Source docs touched

- PRODUCT.md: sim
- ARCHITECTURE.md: sim (invites/membership)
- INTEGRATIONS.md: não
- ADR required: possível (representação do invite) — a decidir na arquitetura
- Operator packet required: sim
