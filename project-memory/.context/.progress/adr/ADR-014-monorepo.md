# ADR-014 — Monorepo (pnpm + Turborepo)

- **Status:** accepted (2026-08-09)
- **Contexto:** desktop, mobile, JanjaNode, rendezvous + muitos packages compartilhados;
  protocolo/crypto/networking precisam de versão única.
- **Decisão:** monorepo pnpm + Turborepo em `workspaces/janjacord/janjacord/` com apps/
  (desktop, mobile, janjanode, rendezvous, push), packages/ (domain, protocol, crypto,
  networking, realtime, permissions, schemas, identity, persistence, design-tokens, testing),
  infra/ (rendezvous, stun, turn, docker, release) e docs/ (protocol, threat-model, self-hosting).
- **Consequências:** um pipeline de build/teste; protocolo/crypto com uma fonte de verdade;
  CI precisa buildar Rust (UniFFI) + WASM + Electron + RN; disciplina de boundaries por package.
- **Refs:** contrato congelado §52, §57
