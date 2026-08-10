# PHASE-CLOSEOUT — Fechamento 100% (2026-08-09, segunda onda)

> Fecha os itens que estavam parciais/não implementados da primeira entrega. Release call: **go_with_named_risk**.

## O que foi fechado nesta onda

| Item (antes parcial) | Entrega | Evidência |
|---|---|---|
| **Rendezvous central** | `apps/rendezvous` (register/resolve, TTL 2h, rate limit/IP); invite carrega serverId; join sem URL manual | smoke-rendezvous 6/6 |
| **Admin UI** | members (kick/ban/assign role), roles editor (criar + flags), settings (retention/privacy), invites (listar/revogar) | smoke-ui screenshots 05-08 (render real) |
| **Media mesh 2 peers** | 2 desktops Electron com câmera/mic sintéticos trocando streams via mesh; tiles de vídeo reais | smoke-media-mesh: `mesh-peer1-final.png`/`mesh-peer2-final.png` (vídeo fake renderizado, ~2600 cores) |
| **Lease automático** | réplica monitora primary (ping); snapshot inicial; promoção automática com epoch (fencing) | smoke-lease 5/5 (failover sem intervenção) |
| **Abuse/rate limits** | malformed flood → socket fechado; max 8 conexões/IP; host sobrevive a fuzz | smoke-fuzz 4/4 |
| **Push service** | `apps/push`: device.register (token isolado do host), host.ping, payload 100% estático; provider mock testável | smoke-push 4/4 (payload `{"title":"JanjaCord","body":"New activity on JanjaCord"}`) |
| **Mobile** | telas completas em código (onboarding/link QR, servers, chat, call com rn-webrtc, push pref) | código em `apps/mobile/src/App.tsx`; build = blocker SDK (honesto) |
| **Updates** | electron-builder (win/mac/linux) + autoUpdater generic (latest.yml) | config no package.json do desktop |

## Bateria final

- Build 12/12 · Typecheck 21/21 · **28 testes unitários + 71 checks de smoke (9 smokes) = 99 verificações**
- Smoke-ui Electron real: 8 screenshots (login → home+QR → server → mensagem E2EE → settings tabs)
- Media mesh visual: 2 peers com vídeo fake renderizado

## Riscos residuais (nomeados — go_with_named_risk)

1. **Mobile build** (Android/iOS): SDK/device ausentes — código 100%, build externo.
2. **Push real**: credenciais FCM/APNs são config (provider mock testado).
3. **Deploy de infra** (rendezvous/coturn/push/updates): configs prontas; servidor externo.
4. **Auditoria externa mls-rs** antes de release público (ADR-005).
5. **Mídia real entre humanos**: transporte+mesh testado com devices sintéticos; áudio/vídeo perceptível exige hardware.
6. **UniFFI do mls-rs (mobile)**: dependência de build documentada (spec group-crypto) — o desktop usa WASM (funcional).

## Próxima fase

- Evolução V1.1 candidato (screen share) — somente com approval.
- Provisionamento de infra (rendezvous/coturn/push/updates) para uso real.
