# JanjaCord

**Server. Channel. Talk. Nothing else.**

Comunicador privado de comunidades, invite-only, desktop e mobile — focado exclusivamente em
comunicação. Referência filosófica: Signal, não Discord. Do Discord aproveitamos apenas servers,
channels, roles e voice rooms.

- Identidade pseudônima local (sem email, sem telefone)
- Mensagens **E2EE e efêmeras** (read-once: somem quando todos leem; retenção máxima padrão 7 dias)
- Servers **self-hosted** (JanjaNode) — a infraestrutura central é só bootstrap/rendezvous
- Voz/vídeo em **WebRTC mesh P2P**
- **Zero analytics, zero telemetria** — auditorável, open-source por design

## Princípios (não negociáveis)

1. Sem email, sem telefone, sem identidade real obrigatória
2. Entrada em server somente por convite (capability)
3. Conteúdo E2EE (MLS — RFC 9420); nenhum conteúdo legível pela infraestrutura
4. Nenhuma mensagem permanente por padrão; efemeridade real, não DRM
5. Self-hosting como arquitetura; cliente assume CPU/memória/storage/banda
6. Zero observabilidade de usuário; debug local explícito e sanitizado
7. "content-private, pseudonymous, metadata-minimizing" — não prometemos anonimato absoluto

## Stack

```
Monorepo pnpm + Turborepo
├── apps/
│   ├── desktop/      Electron 43 + React + Vite + Tailwind (shadcn-style)
│   ├── janjanode/    NestJS — host do server (membership, spool, signaling, replicas)
│   ├── rendezvous/   bootstrap/discovery por serverId (TTL curto, rate-limited)
│   └── push/         push genérico (payload 100% estático; provider mock + FCM/APNs config)
├── packages/
│   ├── crypto-core/  MLS → WASM (mls-rs 0.55, Rust; pkg versionado — build sem Rust)
│   ├── crypto/       Argon2id (KDF), AES-256-GCM, invites (base32)
│   ├── identity/     vault local, recovery key, device linking (QR)
│   ├── persistence/  SQLite cifrado (SQLCipher raw key)
│   ├── protocol/     envelope versionado, fragmentação, anti-replay
│   ├── permissions/  flags com precedência (deny canal > allow canal > role > default)
│   ├── networking/   HostClient (fila serializada), transports
│   └── schemas/      Zod — validação do wire protocol
└── project-memory/   snapshot da memória operacional do projeto (docs/specs/ADRs/status)
```

**Criptografia:** MLS (RFC 9420) via mls-rs → WASM. Senha nunca é a identidade — apenas protege
o vault local (KEK via Argon2id). Asset keys de anexos viajam dentro do ciphertext MLS (o host
nunca as vê).

## Como rodar

### Requisitos

- Node ≥ 24, pnpm ≥ 10
- Rust + wasm-pack **apenas se quiser recompilar o MLS** (`JC_REBUILD_WASM=1`) — o WASM já está
  versionado, então o build funciona sem Rust (essencial para Windows)

### Instalar e buildar

```bash
pnpm install --no-frozen-lockfile
pnpm build
```

> Windows: instale Node ≥ 24 e `npm install -g pnpm@10`; depois `pnpm install` + `pnpm build`.
> Linux: use `bash scripts/setup-machine.sh` (instala Node/pnpm/Rust se faltar e builda).

### Rodar o app desktop

```bash
cd apps/desktop && node_modules/.bin/electron . --no-sandbox
```

### Testar com 2 contas no mesmo PC (sem 2 máquinas)

Abra 2 terminais:

```bash
# Janela 1 (conta A): cria identidade → cria server → + invite
cd apps/desktop && node_modules/.bin/electron . --no-sandbox

# Janela 2 (conta B): cria identidade → entrar com convite → host ws://127.0.0.1:8931/signal
cd apps/desktop && JC_USERDATA_DIR=/tmp/jc-conta2 node_modules/.bin/electron . --no-sandbox
```

### Testar entre 2 PCs (Linux + Windows)

- Máquina A (host): rodar o app → criar server → copiar o convite `JC2-...` (o convite já
  carrega o endereço do host — IP local/Tailscale detectado automaticamente); liberar a porta
  **8931 TCP** no firewall (e UDP para a call)
- Máquina B: rodar o app → criar identidade → "Entrar com convite" → **colar só o convite**
  (um campo — o endereço vem embutido)

### Testes automatizados (smokes)

```bash
cd apps/desktop
node scripts/smoke-core.mjs       # M1: 2 identidades, E2EE real, purge, sem plaintext no host
node scripts/smoke-call.mjs       # mesh WebRTC + signaling relé
node scripts/smoke-replica.mjs    # replicação + failover
node scripts/smoke-lease.mjs      # lease automático (failover sem intervenção)
node scripts/smoke-rendezvous.mjs # descoberta por serverId
node scripts/smoke-relay.mjs      # relay-only enforcement
node scripts/smoke-fuzz.mjs       # abuse/rate limits
node scripts/smoke-push.mjs       # push genérico (payload estático)
```

## Status

- **Roadmap M0–M4 executado**: build 12/12, typecheck 21/21, 28 testes unitários + 71 checks de
  integração (9 smokes) + smoke-ui Electron real (screenshots) + media mesh entre 2 peers
- **Desktop Linux testado de ponta a ponta**: identidade, server self-host, mensagens E2EE
  efêmeras, anexos, call mesh, roles/permissões, admin UI, replicação/failover, relay-only
- **Blockers externos** (código pronto, ambiente pendente): build mobile Android/iOS (SDK),
  push com credenciais FCM/APNs, deploy de infra (rendezvous/coturn), auditoria externa do
  mls-rs antes de release público, teste com hardware real entre humanos

Detalhes: `project-memory/` (PRODUCT.md, ARCHITECTURE.md, CHECKLIST.md, specs, ADRs, reviews).

## Segurança / privacidade (resumo)

- Nenhum SDK de analytics/tracking no lockfile (auditoria automatizada)
- Electron: contextIsolation + sandbox + preload mínimo (CJS)
- SQLite cifrado (SQLCipher raw key 32B) em todos os bancos; chave errada rejeitada
- Invites: secret não armazenado (hash HMAC); replay rejeitado; quota de spool/attachment;
  rate limits de handshake e conexões
- Relay-only: nunca emite candidates host/srflx (verificado)
- Threat model e não-garantias documentados em `project-memory/`
