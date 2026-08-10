# SPEC — Identity, Local Vault and Recovery

## 1. Slice identity

- Slice / feature / artifact: identidade pseudônima local, vault cifrado, recovery key
- Current phase: Phase 0-1 — definição (TASK-001)
- Target repo or artifact: `specs/` + `packages/identity,crypto,persistence` (futuro)
- Product truth source: PRODUCT.md §2 (Identity; Privacy), contrato congelado §7-§9
- Architecture truth source: ARCHITECTURE.md (identity model; crypto boundary)
- Checklist phase/item: Phase 1 — Foundation
- Primary actor / audience: usuário final (primeira abertura)
- Final-user outcome: identidade criada sem email/telefone; senha só protege o vault local
- Why this matters now: base de tudo; erro aqui compromete a promessa de privacidade

## 2. Confirmed facts (pesquisa 2026-08-09 — StorageScout)

- **Vault híbrido, chave separada da senha:**
  - Gerar localmente com RNG criptográfico (`crypto.randomBytes`/`expo-crypto.getRandomBytes`):
    **seed de identidade (32 B)** + **chave de banco (32 B)**. Nenhum derivado da senha.
  - Senha → **KEK 32 B via Argon2id** (RFC 9106). KEK cifra seed + dbKey com AES-256-GCM;
    blobs cifrados em arquivo de vault + SQLite cifrado.
  - Troca de senha = re-enrolar blobs (re-wrap), não re-derivar identidade.
- **SQLite cifrado com SQLCipher raw key** (`PRAGMA key = "x'<64hex>'"`) — nunca passphrase
  (KDF interno do SQLCipher é PBKDF2 fraco).
- **Secure storage do SO** (safeStorage/Keychain/Keystore) guarda SÓ valores pequenos
  (token opcional de unlock, credenciais de linking); nunca o vault inteiro (~2 KB limit iOS).
- **KDF:** Argon2id, salt 16 B; baseline RFC 9106 m=64MiB/t=3/p=4 (segunda recomendada),
  OWASP mínimo m=19MiB/t=2/p=1; alvo 0,5–1,0 s no hardware. Desktop: `crypto.argon2Sync`
  (Node ≥ 24.7 → Electron ≥ 43) ou node-argon2; Mobile: `react-native-quick-crypto`
  (argon2 nativo JSI) ou noble-hashes (fallback JS puro). PBKDF2 600k só se FIPS.
- **keytar arquivado** (verified) — não usar. **safeStorage** é a API nativa do Electron
  (async; detectar backend `basic_text` no Linux = sem proteção).
- **SQLite desktop:** `better-sqlite3-multiple-ciphers` (SQLCipher-compat, cross-platform);
  `@journeyapps/sqlcipher` sem Windows — descartado. Mobile: `expo-sqlite` `useSQLCipher:
  true` (dev build; não roda no Expo Go) ou `op-sqlite`.
- **Backup Android:** excluir SecureStore do Auto Backup (config plugin) senão restaura quebra.
- **iOS:** Keychain persiste após uninstall — risco para efêmeros (tratar).
- Identidade = seed de alta entropia (ed25519/x25519 + MLS); senha NUNCA participa de
  assinaturas/handshake/linking.
- Perda da senha = perda dos dados locais (por design); fluxo: reset local + re-link.
- Recovery: senha errada detectada por falha AES-GCM; recuperação via Recovery Key/export.

## 3. Open decisions

- Recovery key exata (mnemônico BIP39 vs seed hex vs export de arquivo):
  - Why: UX de backup vs robustez.
  - Options: (a) mnemônico 24 palavras (BIP39) do seed — padrão, auditável, escrevível em papel;
    (b) export de arquivo cifrado; (c) ambos. Recomendado: (a) + opção (b) no desktop;
    recovery key NUNCA via central. Owner: product-owner + security. Blocking: sim (onboarding).
- Mecanismo de unlock rápido opcional (biometria): token no secure storage com
  `requireAuthentication` + fallback por senha (invalidado por mudança de biometria).
- Quanto do vault vai para backup: nada automático (privacy-first); recovery key é o caminho.

## 4. Real behavior contract

- Entry point: primeira abertura → Welcome → nickname + senha → Create identity.
- Main actions:
  1. Gera seed identidade (32 B) + dbKey (32 B) com RNG criptográfico.
  2. Deriva KEK = Argon2id(senha, salt 16 B aleatório; parâmetros persistidos).
  3. Cifra seed + dbKey com AES-256-GCM (nonce/tag persistidos) → vault file.
  4. Inicializa SQLite cifrado (raw key) para dados locais.
  5. Mostra Recovery Key UMA vez (mnemônico + export opcional); confirmação de anotação.
  6. Desbloqueio: senha → KEK → decifra seed/dbKey → app operacional (vault em memória).
  7. Troca de senha: re-wrap blobs com nova KEK (seed/dbKey intactos).
  8. Recovery: usuário com recovery material (mnemônico/export) restaura identidade
     (re-cifra com nova senha).
- Data required: senha, salt, parâmetros KDF, blobs cifrados, recovery material.
- Persistence or side effect: vault file + SQLite cifrado no disco local; secure storage
  opcional (token unlock).
- Integrations/API calls: safeStorage (desktop) / expo-secure-store (mobile), SQLCipher,
  Argon2id (node:crypto / quick-crypto / noble).
- Completion state: identidade criada e recuperável com recovery material; vault fechado
  ao sair; senha nunca transmitida.
- What must not be mocked: KDF real, cifragem real, recovery real.

## 5. Required states and failures

- Loading: KDF em execução (0,5–1 s) — UX com spinner honesto.
- Empty: primeira abertura.
- Error: senha errada → erro claro (falha de tag AES-GCM); sem retry infinito.
- Invalid input: senha fraca (política mínima), nickname vazio.
- Unauthorized: n/a.
- Slow dependency: Argon2 em hardware fraco (parâmetros adaptados; mobile < desktop).
- Partial failure: corrupção do vault file → erro com opção de recovery.
- Retry/recovery: recovery key restaura identidade; re-link de devices após reset local.

## 6. Acceptance criteria

- [ ] Seed de identidade e dbKey gerados localmente (RNG criptográfico); senha não os deriva
- [ ] KEK via Argon2id com parâmetros documentados; blobs AES-256-GCM no disco
- [ ] SQLite cifrado com raw key (nunca passphrase)
- [ ] Recovery key mostrada uma vez, exportável; recovery restaura a identidade
- [ ] Troca de senha re-enrola sem alterar identidade/dbKey
- [ ] Secure storage contém apenas valores pequenos (token unlock), não o vault
- [ ] Vault fechado ao sair; senha nunca sai do device
- [ ] Nenhum caminho de recuperação central (sem backdoor de private key)

## 7. Mock and placeholder policy

- Allowed only as internal draft: n/a.
- Explicitly blocked for final: senha como identidade, KDF mock, recovery falso.
- Label required if mock remains: `MOCK`.
- Follow-up required before release: spike de ABI Electron (rebuild better-sqlite3) e
  raw key via expo-sqlite [INFERENCE — confirmar].

## 8. Client/public language gate

- Terms that must not appear: "password recovery por email", "conta", "backup automático".
- Claims that require proof: "senha protege apenas o vault" — código + review.
- Buyer/client language replacements: "sua identidade vive só no seu device", "chave de
  recuperação anotada uma única vez".

## 9. (não aplicável)

## 10. Evidence required before checklist completion

- Testes de KDF/cifragem/recovery (vitest)
- Spike: raw key em expo-sqlite + ABI better-sqlite3 no Electron
- Operator-test: criar identidade, fechar, reabrir, trocar senha, recuperar

## 11. Checklist projection

- Checklist file: CHECKLIST.md — Phase 1
- Item(s): identity keypair, vault, KDF, recovery, secure storage
- Acceptance rule: `[x]` com testes + operator-test de recovery
- Evidence links: QA-REVIEW; SECURITY-REVIEW

## 12. Source docs touched

- PRODUCT.md: sim
- ARCHITECTURE.md: sim (identity model; crypto boundary)
- INTEGRATIONS.md: sim (safeStorage, Keychain/Keystore, SQLCipher, Argon2)
- ADR required: ADR-001 (pseudonymous local identity) + ADR-002 (no-email/no-phone)
- Operator packet required: sim
