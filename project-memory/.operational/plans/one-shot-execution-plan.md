# Plano One-Shot — Execução 100% da Checklist JanjaCord (loop contínuo)

> Modo: loop até desenvolver 100% da CHECKLIST.md e entregar app testado (M0 aprovado pelo dono
> em 2026-08-09). Prontidão técnica fechada por 4 scouts (ReadyMls/ReadyWebRtc/ReadyStorage/
> ReadyElectronNode) — APIs de 2026 verificadas em docs oficiais.

## Definição de "sem residuais" (honesta)

- Cada fase termina com acceptance criteria verificados por evidência (testes verdes, smoke real,
  operator-test packet) — NÃO por scaffold/boilerplate.
- Dependências externas irreversíveis (device iOS real, contas Apple/Google p/ push/assinatura,
  servidor público p/ rendezvous/TURN, runners CI win/mac) ficam EXPLÍCITAS como blockers com
  ação exata — nunca "feito por aproximação".
- Testável nesta estação (Linux): desktop Electron, JanjaNode (Node), protocolo, E2EE MLS real,
  spool/purge, invites/roles/permissions, attachments, WebRTC voice/video local (mesh),
  replicação local (2 hosts), mobile Android (se SDK disponível; senão blocker explícito).

## Decisões de prontidão aplicadas

1. **JanjaNode = processo Node separado** (child_process.fork/standalone), não embed no Electron:
   usa prebuilds nativos (better-sqlite3-multiple-ciphers, node-datachannel) SEM rebuild ABI;
   desktop conecta via WebSocket localhost (`/signal`). Isolamento de crash/CPU bônus.
2. **Crypto MLS = crate Rust wrapper `janjacord-mls` → WASM** (wasm-pack, wasm-bindgen,
   RUSTFLAGS `--cfg mls_build_async`; provider RustCrypto feature browser); consumido no main
   process do Electron (Node ESM) e em testes Node. Renderer pede via IPC (sandbox mantido).
3. **Vault desktop**: KEK = `crypto.argon2` async (Node 24.18.1) → AES-256-GCM wrap do seed +
   dbKey; SQLite cifrado = better-sqlite3-multiple-ciphers `cipher='sqlcipher'`+`legacy=4` +
   `db.key(Buffer)` raw 32B; safeStorage async SÓ p/ token de unlock opcional; gate `basic_text`
   no Linux (não persistir chaves E2EE se basic_text — fallback senha a cada unlock).
4. **Mobile (Android)**: expo-sqlite `useSQLCipher` + `PRAGMA key = x'hex'` (64 hex raw, interop
   desktop); react-native-webrtc 124.0.8 + config plugin; quick-crypto argon2 (dev build).
5. **Signaling**: `@nestjs/platform-ws` + `WsAdapter` path `/signal`, protocolo `{event,data}`,
   validação zod nos handlers; perfect negotiation SDP/ICE.
6. **Update**: `electron-updater` provider `generic` (latest.yml servido pelo JanjaNode) —
   arquitetura; deploy real = blocker externo (servidor).

## Ordem de execução (loop)

### Phase 1 — Foundation
1. Check toolchain (node ≥22, pnpm ≥9, rust + wasm32-unknown-unknown + wasm-pack; instalar o que faltar)
2. Monorepo scaffold: `workspaces/janjacord/janjacord/` — pnpm-workspace.yaml, turbo.json,
   tsconfig base, package.json raiz, .gitignore
3. `packages/schemas` (Zod: envelope, comandos, invites, permissions, presence)
4. `packages/crypto-core` (Rust: jac-jacord-mls wrapper wasm) — criar grupo, add/remove member,
   encrypt/decrypt, key lifecycle; build wasm + smoke test em Node
5. `packages/crypto` (TS): KDF argon2 params, AES-GCM wrap, raw key helpers, interface adapter
6. `packages/identity` (TS): seed, keypair, vault file, recovery key, device linking
7. `packages/persistence` (TS): SQLCipher open (raw key), migration, secure_delete purge
8. `packages/protocol` (TS): envelope encode/decode, versioning, fragmentação 64KiB, anti-replay
9. `packages/domain` + `packages/permissions`: entidades, flags, precedência, overrides
10. `packages/networking` (TS): DirectTransport/HostTransport interfaces; node-datachannel adapter
11. Testes vitest unitários por package; security review local (identity/crypto)

### Phase 2 — Server & Membership (JanjaNode)
12. `apps/janjanode`: NestJS modular (identity/server/membership/roles/channels/invites/
    permissions/presence/hosting) + `@nestjs/platform-ws` gateway `/signal` + zod
13. Invite capability (assinatura owner, expiração/limites/revogação, anti-replay)
14. Permission evaluation (precedência documentada) + kick/ban por identidade + ownership transfer
15. Spool: SQLCipher storage de envelopes pendentes + purge/retention (7d default)
16. Op-log append-only (base replicação) + 2-safe p/ config
17. Testes integração (2 clients ↔ host real via WS); operator smoke

### Phase 3 — MVP Text E2EE (M1)
18. Desktop Electron: main (safeStorage gate, argon2, IPC, WS client p/ JanjaNode), preload ESM,
    renderer React (onboarding, server rail, channel list, conversation, composer, reactions)
19. Integração MLS: envelope cifrado via WASM no main; entrega P2P (DC node-datachannel) + spool
20. Consumo (RENDERED→CONSUMED) + ACK idempotente + purge global + max retention
21. OPERATOR-TEST-PACKET-MVP: 2 instâncias desktop Linux; identidade + server + invite + E2EE
    real + purge; inspeção de spool sem plaintext
22. Benchmarks iniciais de mesh (guardrail voz/vídeo) — medir cedo

### Phase 4 — Realtime Voice/Video
23. Call signaling (WS perfect negotiation) + WebRTC mesh desktop (nativo Chromium)
24. STUN local + coturn opcional; direct preferred; falha segura
25. Call UI (grid, mic/camera/deafen/leave); smoke local 2 peers

### Phase 5 — Attachments + Replicas
26. Attachment: cifragem local AES-GCM, chunks 64KiB + manifest, retry, quotas/TTL, purge
27. Replicas: réplica autorizada + op-log catch-up + lease/fencing simples + failover
28. Testes de falha real (kill primary) + recovery

### Phase 6 — Mobile + Multi-device + Push
29. Device linking QR (desktop↔mobile) + revogação
30. Mobile Android (se SDK/emulador disponível): onboarding, servers/channels/conversation, call
31. Push genérico (arquitetura + payload estático; real = blocker contas Google/Apple)

### Phase 7 — Relay-only + Polimento
32. Relay-only enforcement (candidates ICE) + self-host TURN config + falha segura
33. Empty/error/edge states completos; acessibilidade; dark mode

### Phase 8 — Release Hardening
34. Code review (self + reviewer), QA funcional (acceptance PRODUCT.md §7), security review
    (threat model, auditoria deps — zero SDK tracking)
35. OPERATOR-TEST-PACKET-RELEASE; relatório final com estado por fase e blockers externos

## Verificação contínua (por slice)

- Teste do contrato do slice (vitest) verde ANTES de avançar
- Smoke executável do slice (comando real, não mock)
- Evidence em `.memory/.operational/artifacts/TASK-001/` + reviews/
- Nada de fase completa por scaffold: `[x]` exige comportamento com evidência

## Stop conditions

- Fase atual 100% verificada E próxima fase iniciada, até CHECKLIST completo
- Blocker externo real (device/contas/servidor/assinatura) → registrar blocker explícito com
  ação exata, continuar o que é completável
- Nunca yield por slice verde: loop continua até o fim ou blocker honesto
