# ADR-011 — Host Replication & Failover (single-writer + lease + fencing)

- **Status:** accepted (2026-08-09) — research ReplicationScout
- **Contexto:** server não deve morrer com o PC do owner; sem infra central confiável; sem
  sistema distribuído acadêmico.
- **Decisão:** primary single-writer + réplicas warm-standby assíncronas; op-log append-only
  (state machine replication sem consenso); lease TTL ~60–120s renovado por heartbeat
  (réplicas + rendezvous); fencing por epoch monotônico (clientes rejeitam epoch menor);
  durabilidade 2-safe (ACK ≥1 réplica) para config/membership/crypto, best-effort para
  mensagens/attachments/receipts; failover bully determinístico/arbitragem rendezvous + owner
  override; partition mode (message segue; membership/config sob gate — protege RFC 9420 §14).
  Raft/Paxos e CRDT rejeitados (quórum indisponível em desktops; epochs MLS exigem single-writer).
- **Consequências:** membros podem perder mensagens efêmeras (tolerado); perda de
  membership/config/crypto não ocorre com falha de host único; split-brain residual limitado e
  documentado; complexidade real de implementação (lease/fencing/op-log) orçada.
- **Spec:** `server-hosting-and-replication.md`, `host-failure-recovery-and-replication.md`
- **Refs:** etcd leases; ZK leader election recipe; PostgreSQL warm standby; RFC 9420 §14
