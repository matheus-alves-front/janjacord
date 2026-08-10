# ADR-007 — Direct vs Relay Network Privacy Policy

- **Status:** accepted (2026-08-09)
- **Contexto:** peers podem se conectar direto (metadata observável entre eles) ou via relay
  (metadata concentrada no relay). Nenhum modo é "invisível".
- **Decisão:** policy por server escolhida pelo Owner: **Direct preferred** (P2P + TURN
  fallback) ou **Relay only** (nunca rota direta; relay configurado/self-host; fallback público
  JanjaCord só explícito e visível). Relay-only sem relay → falha segura (bloqueia, não degrada
  para direct). Conteúdo E2EE nos dois modos.
- **Consequências:** relay-only aumenta custo/banda central; falha segura pode impedir a
  chamada (UX clara); enforcement via candidates ICE (sem host/srflx em relay-only) +
  iceTransportPolicy:'relay' + deny lists no TURN.
- **Spec:** `direct-vs-relay-privacy-policy.md`, `rendezvous-nat-stun-turn.md`
- **Refs:** RFC 8827 §6.4, RFC 8656 §1
