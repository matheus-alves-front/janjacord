# SPEC — Multi-device Linking and Revocation

## 1. Slice identity

- Slice / feature / artifact: desktop + mobile representando a mesma identidade; revogação
- Current phase: Phase 0-1 — definição (TASK-001)
- Target repo or artifact: `specs/` + `packages/identity,crypto,protocol` (futuro)
- Product truth source: PRODUCT.md §2 (Identity; Device linking), contrato congelado §8, §11
- Architecture truth source: ARCHITECTURE.md (identity model; device keys)
- Checklist phase/item: Phase 6 — Mobile + Multi-device
- Primary actor / audience: usuário com desktop e mobile
- Final-user outcome: mesma identidade em dois devices; revogar um device sem perder a identidade
- Why this matters now: multi-device na V1 exige protocolo de linking seguro (sem transmitir
  private key em plaintext)

## 2. Confirmed facts

- Fluxo desejado (LOCKED): desktop Settings → Devices → Add device → QR; mobile escaneia
  (Link existing identity). Depois ambos representam a mesma identidade.
- Não transformar nickname em conta central tradicional.
- Device revocation deve ser especificado (contrato).
- Senha protege só o vault local (identity-local-vault-and-recovery.md); linking NÃO depende
  da senha — usa sessão de alta entropia efêmera (StorageScout).
- Identidade = seed local (32 B) + device keys; MLS group tem device keys por device
  (ver `group-crypto-and-key-lifecycle.md`).
- Sem conta central; linking é par-a-par assistido (QR contém material efêmero).

## 3. Open decisions

- Conteúdo do QR: sessão efêmera (chave pública do novo device + prova de posse da identidade)
  com TTL curto e escopo único (um device por scan), em vez de transmitir seed/private key.
  Owner: security (gate). Blocking: sim.
- Autorização: novo device assinado pelo device existente (chave de identidade) → o par
  adiciona a device key ao grupo MLS (ver spec crypto). Se o desktop for o único device e cair,
  recovery key re-estabelece.
- Revogação: remover device key do grupo MLS + denylist local; confirmar impacto em
  mensagens pendentes (device revogado não recebe mais).

## 4. Real behavior contract

- Entry point: desktop abre Add device → QR; mobile escaneia.
- Main actions:
  1. Desktop gera sessão de linking efêmera (nonce, TTL curto, escopo 1 device).
  2. Mobile escaneia → envia chave pública do novo device + prova de posse → desktop autentica
     e autoriza (assinatura da identidade).
  3. Novo device recebe material de identidade enrolado (re-encrypted para sua chave) —
     nunca private key em plaintext no QR.
  4. Device key registrada no grupo MLS (Commit) → participa do canal como mesma identidade.
  5. Revogação: usuário remove device em Settings → device key removida do MLS; device
     revogado perde acesso a estados futuros; pendências daquele device expiram.
- Data required: sessão efêmera, device keys, prova de posse, estado MLS.
- Persistence or side effect: device key no vault local + grupo MLS; registro de device no
  server (permissão de consumo por identidade — ver purge spec).
- Integrations/API calls: MLS (device key commit), QR, transporte.
- Completion state: dois devices ativos na mesma identidade; revogação efetiva.
- What must not be mocked: prova de posse real, commit MLS real, revogação real.

## 5. Required states and failures

- Loading: scan em andamento.
- Empty: nenhum device além do atual.
- Error: QR expirado/inválido; escopo já usado (replay) → rejeitar.
- Invalid input: QR malformado.
- Unauthorized: device revogado tenta reconectar → rejeitado pelo grupo.
- Slow dependency: host offline para Commit MLS → linking aguarda (com feedback claro).
- Partial failure: commit aplicado mas device não recebeu → re-sincroniza no reconnect.
- Retry/recovery: device perdido + recovery key → re-estabelece identidade e re-linka.

## 6. Acceptance criteria

- [ ] QR com sessão efêmera (TTL curto, escopo 1 device); private key nunca em plaintext
- [ ] Mobile linked vira a mesma identidade e participa dos mesmos canais
- [ ] Revogar device remove o acesso a estados futuros (teste com device revogado)
- [ ] Replay do QR (mesmo nonce) é rejeitado
- [ ] Device revogado não recebe pendências novas
- [ ] Recovery key re-estabelece identidade após perda de todos os devices

## 7. Mock and placeholder policy

- Allowed only as internal draft: n/a.
- Explicitly blocked for final: linking sem prova de posse, revogação fake.
- Label required if mock remains: `MOCK`.
- Follow-up required before release: teste de revogação em grupo MLS.

## 8. Client/public language gate

- Terms that must not appear: "chave privada", "MLS" na UI.
- Claims that require proof: "revogado perde acesso" — teste.
- Buyer/client language replacements: "vincule seu celular", "remova este dispositivo".

## 9. (não aplicável)

## 10. Evidence required before checklist completion

- Teste de linking real (desktop+mobile)
- Teste de revogação (device revogado sem acesso futuro)
- Operator-test: linkar, revogar, recuperar com recovery key

## 11. Checklist projection

- Checklist file: CHECKLIST.md — Phase 6
- Item(s): linking QR, device keys, revocation, recovery
- Acceptance rule: `[x]` com testes + operator-test
- Evidence links: QA-REVIEW; SECURITY-REVIEW

## 12. Source docs touched

- PRODUCT.md: sim
- ARCHITECTURE.md: sim (device keys)
- INTEGRATIONS.md: sim (MLS, QR)
- ADR required: ADR (multi-device) — parte de ADR-001/ADR-005
- Operator packet required: sim
