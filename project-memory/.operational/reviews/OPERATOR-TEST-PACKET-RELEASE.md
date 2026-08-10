# OPERATOR-TEST-PACKET-RELEASE — JanjaCord (M1/M2/M3/M4 desta estação)

> Como o dono testa pessoalmente o que está operacional nesta estação (Linux), com o que foi
> verificado automaticamente e o que exige dependência externa (blocker explícito).

## 1. Pré-requisitos

- Estação Linux com Node ≥ 24, pnpm ≥ 10, Rust + wasm32 + wasm-pack (toolchain já instalada aqui).
- `cd workspaces/janjacord/janjacord && pnpm install && pnpm build`

## 2. Teste real do app desktop (UI — verificado via smoke automático com screenshots)

```bash
cd apps/desktop
pnpm build                                    # builda o renderer (Vite)
env JC_SMOKE_UI=1 JC_SMOKE_CREATE_IDENTITY=1 JC_SMOKE_DIR=/tmp/jc-shots node_modules/.bin/electron . --no-sandbox
```

Fluxo verificado (screenshots em `.memory/.operational/artifacts/TASK-001/desktop-smoke/`):
1. **Login** — tela "Desbloquear identidade" (vault + Argon2id real).
2. **Home** — "Criar server (self-hosted)", "Vincular dispositivo (QR)", "Entrar com convite".
3. **Server** — criação real: host JanjaNode child + canal #general + membro "matheus".
4. **Mensagem E2EE** — "ola mundo cifrado" cifrada com MLS (wasm), transmitida ao host (ciphertext
   apenas), decifrada localmente e exibida como "você".

Para uso manual interativo: rode `node_modules/.bin/electron . --no-sandbox` sem env de smoke.

## 3. Fluxo M1 completo (2 identidades — verificado via smoke-core, 22 checks)

```bash
cd apps/desktop && node scripts/smoke-core.mjs
```

O que o script prova (e o dono pode repetir manualmente com 2 desktops):
- Identidades pseudônimas locais + recovery key
- Server self-hosted (JanjaNode child) + invite JC1-… + join por convite
- MLS: key packages, add_member, welcome, join_group (epoch ≥ 1)
- **E2EE real bidirecional** (alice ↔ bob) — host vê apenas ciphertext
- Purge global após consumo; **spool do host sem nenhum plaintext** (inspeção do SQLCipher)
- Attachment E2EE: asset key dentro do ciphertext MLS; chunks cifrados no host; bytes íntegros
  no receptor

## 4. Voz/vídeo (mesh — verificado via smoke-call, 8 checks)

```bash
cd apps/desktop && node scripts/smoke-call.mjs
```

- Canal de call com permissões (join_call) e limites
- Signaling relé pelo host (offer/answer/candidates)
- **DataChannel P2P real via mesh** ("ola via mesh" entre 2 peers)
- Media (mic/camera) exige hardware/permissão — testar manualmente na UI de call do desktop
  (canal 🔊 → join → grid; controles mic/câmera/leave)

## 5. Replicação/failover (verificado via smoke-replica, 11 checks)

```bash
cd apps/desktop && node scripts/smoke-replica.mjs
```

- Snapshot do DB cifrado → réplica com o MESMO serverId e estado durável (membros/canais)
- Kill do primary → promoção da réplica (epoch+1, fencing)
- Server continua operacional (escritas e reconexão funcionam)

## 6. Relay-only (verificado via smoke-relay, 3 checks)

```bash
cd apps/desktop && node scripts/smoke-relay.mjs
```

- `iceTransportPolicy: 'relay'` → nenhum candidate host/srflx emitido (enforcement ADR-007)
- Policy direct emite candidates host (controle)

## 7. Suíte automatizada

```bash
pnpm test        # 28 testes (schemas, protocol, permissions, crypto, identity, persistence, crypto-core)
pnpm build       # 10/10 packages (inclui WASM MLS)
pnpm typecheck   # 19/19
cd apps/janjanode && node dist/smoke.js   # 8 checks de integração do host
```

## 8. Dependências externas (blockers honestos — NÃO são residuais do código)

| Item | Estado | Blocker | Ação exata |
|---|---|---|---|
| Mobile Android/iOS (apps/mobile) | scaffold pronto (Expo) | Android SDK/emulador/device iOS ausentes nesta estação | `cd apps/mobile && pnpm install && pnpm android` num host com SDK; device real para WebRTC |
| Push genérico | arquitetura documentada (spec + INTEGRATIONS) | credenciais FCM/APNs + push service central | provisionar contas Google/Apple; deploy do push service |
| STUN/TURN self-host (coturn) | enforcement no cliente; config documentada | deploy de servidor (infra) | docker coturn (portas 3478/5349 + relay UDP) conforme INTEGRATIONS |
| Assinatura/updates desktop | electron-updater configurado (generic) | code-sign certs + servidor de updates | provisionar certs + servir latest.yml |
| Teste em device real (mic/camera, iOS New Arch) | smoke de transporte ok | hardware | testar UI de call em device físico |

## 9. Limitações conhecidas (desta entrega)

- Mesh de call: guardrails 10 voz / 6 câmeras configurados no host; benchmarks reais de
  WAN pendentes (hipótese a medir — ADR-006).
- MLS: mls-rs sem auditoria externa publicada — planejar auditoria antes de release público
  (ADR-005). Commit de membership é broadcast local (2+ membros: o welcome chega ao novo;
  demais peers precisam do commit — melhoria documentada).
- Replicação: snapshot + promoção manual/semi-automática; split-brain residual tratado por
  epoch (fencing) — melhoria de lease automático documentada (ADR-011).
- WASM MLS roda no main process do Electron (Node); renderer usa IPC (sandbox mantido).
- Linux: safeStorage `basic_text` detectado — fallback por senha (ADR-016).
