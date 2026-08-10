# Matriz de Conhecimento Técnico — JanjaCord (gap analysis, 2026-08-09)

> **UPDATE 2026-08-09 (tarde): gaps fechados.** Scouts ReadyMls/ReadyWebRtc/ReadyStorage/
> ReadyElectronNode verificaram as APIs de 2026 em docs oficiais (mls-rs 0.55.3 + mls-rs-uniffi
> 0.13.0 ativo; react-native-webrtc 124.0.8 + config plugin; expo-sqlite PRAGMA key raw 64hex;
> better-sqlite3-multiple-ciphers cipher='sqlcipher'+legacy=4; node:crypto argon2 no Electron
> 43.3/Node 24.18.1; safeStorage async; session permission handlers; WsAdapter NestJS;
> electron-updater generic). Ver plano one-shot p/ decisões de execução aplicadas.

> Autoavaliação honesta do main agent antes da execução one-shot. Nível: o que está no
> conhecimento estável do modelo vs o que exige verificação em docs oficiais (cutoff < 2026).
> A coluna "Ação" reflete o que já foi verificado (scouts TASK-001) e o que os scouts de
> prontidão (Ready*) confirmaram.

## Legenda

- **Estável:** conhecimento de padrões/RFCs/conceitos — confiável sem reconsulta
- **Instável:** APIs/versões de libs de 2026 — exige docs oficiais (scouts Ready*)
- **Ação:** verificado | a verificar (Ready*) | spike na execução | risco residual

## Stack core

| Tecnologia | Nível | Conhecimento | Ação |
|---|---|---|---|
| TypeScript/React/Vite | Estável | Domínio completo (tipos, hooks, estado, build) | — |
| Zustand / TanStack Query | Estável | Padrões de estado/async bem conhecidos | — |
| Tailwind + shadcn/ui | Estável | Design tokens, componentes, dark mode | — |
| Electron (arquitetura) | Estável | main/preload/renderer, contextIsolation, sandbox, IPC | — |
| Electron 43 APIs (safeStorage async, session permission handlers, Node 24 argon2) | Instável | Detalhes de versão 2026 | ReadyElectronNode |
| NestJS (modular, guards, pipes, WebSocket gateway) | Estável | Padrão completo | — |
| NestJS standalone em processo Electron (host no desktop) | Instável | Integração específica | ReadyElectronNode |
| pnpm + Turborepo | Estável | workspaces, pipelines, caching | — |
| Turbo pipeline com native builds (Rust/UniFFI/WASM) | Instável | Orquestração de build nativo | ReadyElectronNode |

## Crypto / identidade (risco máximo)

| Tecnologia | Nível | Conhecimento | Ação |
|---|---|---|---|
| MLS RFC 9420 / RFC 9750 (conceitos, epochs, Commits, FS/PCS, DS/AS) | Estável | Domínio do protocolo | — |
| mls-rs (arquitetura: core Rust, WASM, UniFFI) | Estável | Escolha validada (TASK-001) | — |
| mls-rs 0.55 API concreta (Client, group, KeyPackage, PrivateMessage, storage sqlite) | Instável | API de versão 2026 | ReadyMls |
| WASM no Electron/Node (import, RNG, provider) | Instável | Passos concretos | ReadyMls |
| UniFFI Kotlin/Swift → TurboModule (wrapper próprio) | Instável | Pipeline completo | ReadyMls + spike |
| Argon2id (RFC 9106, parâmetros, node:crypto/quick-crypto/noble) | Estável/Instável | Conceito estável; APIs de versão a confirmar | ReadyStorage |
| AES-256-GCM wrap, raw key SQLCipher | Estável | Domínio completo | — |
| SQLCipher (design, PRAGMA key, secure_delete, WAL) | Estável | Domínio completo | — |
| expo-sqlite useSQLCipher raw key | Instável | API específica | ReadyStorage |
| better-sqlite3-multiple-ciphers (cipher='sqlcipher', legacy, raw key) | Instável | API + prebuilds | ReadyStorage |
| secure storage (safeStorage / expo-secure-store; limites Keychain ~2 KB) | Estável | Fatos verificados (TASK-001) | — |

## Realtime / rede

| Tecnologia | Nível | Conhecimento | Ação |
|---|---|---|---|
| WebRTC (PeerConnection, SDP/ICE, DTLS) | Estável | Domínio completo | — |
| DataChannel (SCTP/DTLS, reliable/ordered, fragmentação, backpressure) | Estável | RFC 8831 + limites verificados (TASK-001) | — |
| STUN/TURN (RFC 8489/8656, coturn, REST credentials) | Estável | Fatos verificados (TASK-001) | — |
| react-native-webrtc 124 (instalação Expo, RTCView, New Arch, permissões) | Instável | API/versão 2026 | ReadyWebRtc |
| node-datachannel (JanjaNode) | Instável | API concreta | ReadyWebRtc |
| Rendezvous (libp2p-style, records assinados, lease) | Estável/Instável | Padrão estável; implementação a desenhar | — |

## Infra / integração

| Tecnologia | Nível | Conhecimento | Ação |
|---|---|---|---|
| coturn deploy (docker, REST auth, hardening) | Estável | Fatos verificados (TASK-001) | — |
| FCM/APNs (payload estático, tokens, background limits) | Estável | Fatos verificados (TASK-001) | — |
| Electron autoUpdate self-host | Estável | Modelo conhecido | ReadyElectronNode (lib 2026) |
| Roteamento de build CI multi-OS (win/mac/linux) | Instável | Necessidade para 5 SOs; a montar | — |

## Plataformas de entrega

| Plataforma | Nível | Conhecimento | Ação |
|---|---|---|---|
| Linux (estação atual) | Estável | Build/smoke local completo | — |
| macOS/Windows | Estável conceitual | Sem smoke local (estação Linux) | CI multi-OS + assinatura |
| iOS | Estável conceitual | Exige hardware Apple + conta dev | dependência externa |
| Android | Estável/Instável | Emulador local possível; device real melhor | smoke emulator |

## Veredito preliminar

- **Coberto com confiança (estável):** arquitetura, protocolo MLS (conceitos), WebRTC/DC,
  SQLCipher, Argon2id, padrões TS/React/RN/Electron/NestJS, coturn, push, rendezvous.
- **Exige verificação ativa (instável — scouts Ready*):** APIs exatas de mls-rs 0.55 (WASM/UniFFI),
  react-native-webrtc 124 (Expo setup), expo-sqlite/secure-store/better-sqlite3-multiple-ciphers
  (raw key), Electron 43 (safeStorage/session/argon2), NestJS no processo Electron,
  Turbo pipeline com native builds.
- **Exige spike na execução (não resolvível só por leitura):** raw key via expo-sqlite
  [UNVERIFIED], rebuild ABI better-sqlite3 no Electron, WASM no Hermes (RN) — caminho mobile é
  UniFFI, wrapper TurboModule + CI Rust multiplataforma.
- **Dependências externas (não são residuais silenciosos):** device iOS/Android real, contas
  Apple/Google (push, assinatura), servidor público (rendezvous/TURN), NAT WAN real, runners CI
  win/mac.

O one-shot é viável se: (1) scouts Ready* fecharem as APIs instáveis; (2) os spikes forem os
PRIMEIROS passos de cada fase (não no meio); (3) dependências externas ficarem explícitas com
ação exata, nunca "feito por aproximação".
