# TASK-002 — Wire Protocol v0 + Crypto Adapter Boundary (proposta — aguardando approval)

## Routing stamp

- execution_mode: heavy-task (implementation slice) — BLOQUEADA até approval do roadmap (M0)
- workflow: development-execucao-segura-de-tarefa
- primary_owner: development-solution-architect (boundaries) + development-backend-engineer
- supporting_specialists: development-security-engineer (gate obrigatório — crypto/protocolo)
- required_gates: security review de envelope/handshake; teste de replay/fragmentação
- target_repo: workspaces/janjacord/janjacord/ (criar monorepo primeiro — ADR-014)
- evidence_required_before_done: schemas Zod + testes de protocolo verdes; wrapper crypto
  com teste de interop MLS (WASM/UniFFI)
- stop_conditions: não implementar UI; não tocar transporte real antes de protocolo aprovado

## Objetivo

Definir e implementar o wire protocol v0 (envelope versionado, ordering, anti-replay) e a
fronteira do adapter crypto (mls-rs WASM/UniFFI com interface TS comum), com testes.

## Escopo

1. Monorepo pnpm+Turborepo scaffoldado (apps/packages minimal — estrutura ADR-014).
2. `packages/schemas`: Zod schemas do envelope/controle (protocolVersion, messageId UUIDv4,
   serverId, channelId, cryptoEpoch, audience commitment, ciphertext ref, attachment refs,
   ordering/anti-replay, expiry).
3. `packages/protocol`: encode/decode + versioning + fragmentação (16–64 KiB) + reassembly +
   anti-replay (nonce + TTL curto).
4. `packages/crypto`: interface única (encrypt/decrypt group message, key lifecycle hooks);
   binding mls-rs WASM (desktop) + UniFFI (mobile) — SPIKE primeiro (wasm no Electron;
   uniFFI no RN; raw key expo-sqlite).
5. Testes: versioning, replay, fragmentação, interop do adapter (sem rede real).

## Aceite

- Envelope versionado trafega encode/decode ida-e-volta; replay rejeitado; fragmentação ok.
- Adapter crypto cifra/decifra com MLS real (não mock) em desktop; spike mobile com resultado
  registrado.
- Security review fechado (envelope + handshake + fragmentação).

## Notas

- Depende: approval do roadmap (M0), spec `realtime-networking-protocol.md`,
  `group-crypto-and-key-lifecycle.md`, `identity-local-vault-and-recovery.md`.
- Spikes obrigatórios antes de congelar bindings (mls-rs WASM no Electron; UniFFI no RN).
