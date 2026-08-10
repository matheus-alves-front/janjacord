# ADR-013 — Wire Protocol Versioning

- **Status:** accepted (2026-08-09)
- **Contexto:** desktop/mobile/host evoluem em versões diferentes; protocolo é auditável e
  independente da UI.
- **Decisão:** todo frame carrega protocolVersion; handshake negocia versão e rejeita
  incompatíveis com erro de upgrade; migração/upgrade documentada por versão; envelope
  versionado com messageId (UUIDv4) + nonce anti-replay (TTL curto de ids no host, sem
  tombstone infinito); ordenação por canal/remetente com reconciliação P2P↔spool.
- **Consequências:** mudanças de protocolo exigem compatibilidade/upgrade path;
  implementações antigas falham com erro claro em vez de corromper; custo de manutenção de
  versões múltiplas durante transições.
- **Spec:** `realtime-networking-protocol.md`, `janjacord-product-contract.md`
- **Refs:** contrato congelado §21 (envelope)
