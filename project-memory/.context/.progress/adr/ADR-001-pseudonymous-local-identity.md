# ADR-001 — Pseudonymous Local Identity

- **Status:** accepted (2026-08-09) — contrato congelado + research StorageScout
- **Contexto:** sem email/telefone; identidade não pode depender de conta central. Senha humana
  tem entropia insuficiente para ser identidade criptográfica.
- **Decisão:** identidade = seed local de alta entropia (32 B, RNG criptográfico) gerado no
  primeiro uso; nickname é pseudônimo server-specific; a autoridade interna é a identidade
  criptográfica. Senha → KEK via Argon2id que cifra o seed (AES-256-GCM); senha NUNCA deriva
  a identidade, nunca participa de assinaturas/handshake/linking. Recovery via recovery key
  (mnemônico/export), exibida uma vez.
- **Consequências:** perda de todos os devices + recovery = perda da identidade (aceito, por
  design, sem backdoor central). Vault local cifrado; linking entre devices usa sessão efêmera
  independente da senha.
- **Spec:** `identity-local-vault-and-recovery.md`, `multi-device-linking-and-revocation.md`
- **Refs:** RFC 9106 (Argon2id); Electron safeStorage; expo-secure-store
