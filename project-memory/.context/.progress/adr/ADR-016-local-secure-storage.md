# ADR-016 — Local Secure Storage (SQLCipher + Argon2id vault)

- **Status:** accepted (2026-08-09) — research StorageScout
- **Contexto:** vault da identidade + dados efêmeros precisam de proteção em repouso nos 5 SOs.
- **Decisão:** vault híbrido: KEK = Argon2id(senha) cifra seed + dbKey (AES-256-GCM) em vault
  file; SQLite cifrado com SQLCipher **raw key** (nunca passphrase — KDF interno fraco);
  secure storage do SO (safeStorage/expo-secure-store) guarda SÓ valores pequenos (token de
  unlock), nunca o vault (~2 KB limit iOS); purge com secure_delete + VACUUM; backup Android
  exclui SecureStore; keytar proibido (arquivado).
- **Consequências:** confidencialidade offline independente do SO; brute-force mitigado por
  Argon2id (memória-hard); Linux basic_text detectado (aviso); troca de senha = re-wrap.
- **Spec:** `identity-local-vault-and-recovery.md`
- **Refs:** RFC 9106; SQLCipher design; Electron safeStorage; expo-secure-store
