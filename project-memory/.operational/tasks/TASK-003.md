# TASK-003 — Identity Local + Vault + KDF (proposta — aguardando approval)

## Routing stamp

- execution_mode: heavy-task (implementation slice) — BLOQUEADA até M0 aprovado
- workflow: development-execucao-segura-de-tarefa
- primary_owner: development-backend-engineer (crypto/identity)
- supporting_specialists: development-security-engineer (gate obrigatório), development-mobile-engineer (secure storage)
- required_gates: security review de vault/KDF/linking
- target_repo: workspaces/janjacord/janjacord/
- evidence_required_before_done: testes de KDF/cifragem/recovery; operator-test de recovery
- stop_conditions: sem UI; sem account central; sem recovery backdoor

## Objetivo

Identidade pseudônima local: seed 32 B (RNG criptográfico), KEK Argon2id(senha) cifrando
seed+dbKey (AES-256-GCM), SQLCipher raw key, recovery key (mnemônico/export), linking QR
efêmero (sessão 1-scan, prova de posse), revogação de device.

## Escopo

1. `packages/identity`: seed, keypair (ed25519/x25519), device keys, recovery material.
2. `packages/crypto`: KDF (node:crypto argon2id no Electron ≥43 / quick-crypto no RN /
   noble fallback), AES-GCM wrap, raw key SQLCipher.
3. `packages/persistence`: vault file + SQLite cifrado (better-sqlite3-multiple-ciphers /
   expo-sqlite useSQLCipher); purge secure_delete.
4. `packages/domain`: linking QR (sessão efêmera, escopo 1 device, prova de posse), revogação.
5. Testes: KDF (parâmetros RFC 9106/OWASP), wrap/unwrap, recovery, revogação, replay do QR.

## Aceite

- Senha nunca deriva identidade; recovery key restaura; troca de senha = re-wrap.
- Secure storage só com valores pequenos; Linux basic_text detectado.
- Security review fechado (vault/KDF/linking).

## Notas

- Depende: TASK-002 (crypto boundary), spec `identity-local-vault-and-recovery.md`,
  `multi-device-linking-and-revocation.md`, ADR-001/015/016.
