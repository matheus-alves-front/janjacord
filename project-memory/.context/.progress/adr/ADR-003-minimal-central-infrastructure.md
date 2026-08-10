# ADR-003 — Minimal Central Infrastructure

- **Status:** accepted (2026-08-09) — research PushRendezvousScout
- **Contexto:** peers/hosts precisam se encontrar e atravessar NAT; algo central é necessário.
- **Decisão:** infra central = rendezvous (records assinados com TTL curto, rate limits, DNS
  SRV/TXT, sem contas), STUN, TURN (coturn, REST credentials), update self-host, push service
  mínimo (payload estático). NUNCA: storage de mensagens/imagens/arquivos/voz/vídeo/histórico/
  search/social graph/analytics. Metadata central mínima, efêmera, documentada no threat model.
- **Consequências:** dependência central pequena e verificável; rendezvous down → joins novos
  bloqueados, tráfego existente segue; TURN é o maior custo central (documentado).
- **Spec:** `rendezvous-nat-stun-turn.md`, `privacy-metadata-and-telemetry-policy.md`
- **Refs:** libp2p rendezvous spec; RFC 8489/8656; coturn wiki
