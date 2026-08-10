# ADR-012 — Encrypted Attachment Transport

- **Status:** accepted (2026-08-09)
- **Contexto:** imagens/arquivos efêmeros; host só pode ver ciphertext; retry/limites reais.
- **Decisão:** asset key aleatória (32 B) por arquivo; AES-256-GCM local; chunks de 64 KiB com
  checksum + manifest (assetId, tamanho, hash); entrega P2P (DC) ou spool host cifrado (offline)
  com retry idempotente por chunk; size limits/quotas/TTL alinhado à retention; purge remove
  ciphertext com a mensagem. Receptores montam, verificam hash, descriptografam localmente.
- **Consequências:** spool de attachments é custo real do host (quotas default 50 MB/arquivo,
  2 GB/server — calibrar); órfãos limpos por TTL; metadados não vazam em plaintext.
- **Spec:** `encrypted-attachment-delivery.md`, `abuse-resource-and-dos-guardrails.md`
- **Refs:** RFC 8831 (DC size); SQLCipher secure_delete
