# ADR-002 — User-hosted Server Model (self-hosting como arquitetura)

- **Status:** accepted (2026-08-09)
- **Contexto:** servers não são VMs centrais; infra central não carrega conteúdo normal.
- **Decisão:** um Server é uma comunidade criptográfica cujo Primary Host é, por padrão, o
  desktop de quem criou (Owner), via JanjaNode (NestJS no desktop/standalone). Replica Hosts
  autorizados garantem continuidade. Central fornece só rendezvous/STUN/TURN/update/push.
- **Consequências:** custo central marginal ≪ volume de comunicação; cliente assume
  CPU/memória/storage/banda; complexidade de replicação/failover cai sobre o produto
  (ADR-011). Server pode ficar indisponível quando todos os hosts offline.
- **Spec:** `server-hosting-and-replication.md`, `host-failure-recovery-and-replication.md`
- **Refs:** contrato congelado §4-§7
