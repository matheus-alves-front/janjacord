# Stack Docs — janjacord

Fonte primária de verdade técnica: docs oficiais/primárias. Registro das fontes efetivamente
consultadas (2026-08-09, TASK-001). [INFERENCE] = inferência; demais = verificado na fonte.

## Push mobile (confirmado — PushRendezvousScout, 2026-08-09)

- FCM: notification vs data messages, payload máx 4096 B, notification sempre collapsible:
  https://firebase.google.com/docs/cloud-messaging/customize-messages/set-message-type
- FCM Android entrega por estado do app (foreground/background):
  https://firebase.google.com/docs/cloud-messaging/android/receive-messages
- FCM Android priority/Doze: https://firebase.google.com/docs/cloud-messaging/android-message-priority
- FCM throttling/quotas: https://firebase.google.com/docs/cloud-messaging/throttling-and-quotas
- FCM token lifecycle (expiração 270d Android, UNREGISTERED): https://firebase.google.com/docs/cloud-messaging/manage-tokens
- APNs payload (4096 B, `aps` dict, sem dados sensíveis):
  https://developer.apple.com/documentation/usernotifications/generating-a-remote-notification
- APNs background não-garantido (throttle 2–3/h): https://developer.apple.com/documentation/usernotifications/pushing-background-updates-to-your-app
- Expo push (tipos, dev build, limites): https://docs.expo.dev/push-notifications/what-you-need-to-know.md
  e https://docs.expo.dev/push-notifications/sending-notifications.md
- Envio direto FCM v1/APNs via Expo: https://docs.expo.dev/push-notifications/sending-notifications-custom.md
- Android 13+ POST_NOTIFICATIONS (off por padrão): https://developer.android.com/develop/ui/compose/notifications/notification-permission
- FCM BigQuery export é opt-in — NÃO habilitar (zero telemetria): https://firebase.google.com/docs/cloud-messaging/understand-delivery

## Rendezvous / P2P bootstrap (confirmado)

- libp2p rendezvous (REGISTER/DISCOVER, TTL 2–72h, signed records, rate limits):
  https://github.com/libp2p/specs/blob/master/rendezvous/README.md
- DNS SRV (RFC 2782): https://www.rfc-editor.org/rfc/rfc2782.html
- DNS-SD (RFC 6763): https://www.rfc-editor.org/rfc/rfc6763.html

## STUN/TURN (confirmado)

- RFC 8489 STUN: https://www.rfc-editor.org/rfc/rfc8489.html
- RFC 8656 TURN (relay oculta endereço real): https://www.rfc-editor.org/rfc/rfc8656.html
- coturn wiki (flags deploy, REST API HMAC-SHA1, quotas): https://github.com/coturn/coturn/wiki/turnserver
  e https://github.com/coturn/coturn/wiki/README
- WebRTC.org TURN server (RTCConfiguration): https://webrtc.org/getting-started/turn-server
- MDN WebRTC protocols (STUN vs TURN no ICE): https://developer.mozilla.org/en-US/docs/Web/API/WebRTC_API/Protocols

## Update distribution (confirmado)

- Electron updates (update.electronjs.org exige repo GitHub público; self-host Hazel/Nuts/Nucleus;
  code-sign obrigatório macOS): https://www.electronjs.org/docs/latest/tutorial/updates

## Fontes de produto referenciadas na definição (a validar durante specs/implementação)

- RFC 8831 WebRTC DataChannel: https://www.rfc-editor.org/info/rfc8831
- RFC 8827 WebRTC Security Architecture: https://www.rfc-editor.org/info/rfc8827
- RFC 8835 Transports for WebRTC: https://www.rfc-editor.org/info/rfc8835
- RFC 9420 MLS: https://www.rfc-editor.org/info/rfc9420
- RFC 9750 MLS Architecture: https://www.rfc-editor.org/info/rfc9750
- RFC 9605 SFrame: https://www.rfc-editor.org/info/rfc9605
- Electron docs: https://electronjs.org/docs/latest
- React Native docs: https://reactnative.dev/docs/environment-setup
- shadcn/ui: https://ui.shadcn.com/docs

## MLS / group E2EE (confirmado — MlsScout, 2026-08-09)

- RFC 9420 (MLS Protocol): https://www.rfc-editor.org/rfc/rfc9420.html
- RFC 9750 (MLS Architecture): https://www.rfc-editor.org/rfc/rfc9750.html
- **mls-rs 0.55.3 (awslabs, Apache-2.0/MIT) — recomendado**: https://github.com/awslabs/mls-rs
  (WASM first-class; sqlite/sqlcipher bundled; interop oficial IETF MLS WG no CI; SEM auditoria
  externa publicada — README)
- openmls 0.8.x (MIT, Phoenix R&D + Cryspen): https://github.com/openmls/openmls
  (CI testa só x86; mobile/wasm buildados sem teste)
- libsignal rejeitado (AGPL-3.0; sem MLS; uso fora da Signal não suportado):
  https://github.com/signalapp/libsignal
- XMTP libxmtp (prova do padrão core Rust MLS + UniFFI): https://github.com/xmtp/libxmtp
- UniFFI: https://github.com/mozilla/uniffi-rs · WASM no Hermes (experimental):
  https://github.com/facebook/hermes/issues/429 · RN 0.84: https://reactnative.dev/blog/2026/02/11/react-native-0.84

## WebRTC Electron + React Native (confirmado — WebRtcScout, 2026-08-09)

- RFC 8831 (Data Channels) / 8832 (DCEP) / 8827 (Security, §6.4 IP privacy) / 8835
  (Transports §3.4) / 8656 (TURN) / 8445 (ICE) / 8841 (SCTP/SDP):
  https://www.rfc-editor.org/rfc/rfc8831.html (e demais IDs)
- MDN RTCDataChannel (size limits ≥256 KiB; default 64 KiB se max-message-size ausente):
  https://developer.mozilla.org/en-US/docs/Web/API/WebRTC_API/Using_data_channels
- Electron: sandbox https://www.electronjs.org/docs/latest/tutorial/sandbox · context-isolation
  https://www.electronjs.org/docs/latest/tutorial/context-isolation · session permission handlers
  https://www.electronjs.org/docs/latest/api/session
- react-native-webrtc 124.0.8 (New Arch RN 0.76+; Android sólido, iOS validar):
  https://github.com/react-native-webrtc/react-native-webrtc · issue New Arch #1557 ·
  npm 124.0.8 https://registry.npmjs.org/react-native-webrtc/latest
- node-datachannel (libdatachannel) p/ JanjaNode: https://github.com/murat-dogan/node-datachannel
- @roamhq/wrtc (fallback API-browser, M106): https://github.com/WonderInventions/node-webrtc
- coturn: https://github.com/coturn/coturn · config exemplo: .../examples/etc/turnserver.conf ·
  Docker https://hub.docker.com/r/coturn/coturn
- Android FGS types (camera/microphone, 14+):
  https://developer.android.com/develop/background-work/services/fgs/service-types ·
  Apple background modes: https://developer.apple.com/documentation/xcode/configuring-background-execution-modes

## Secure storage / vault (confirmado — StorageScout, 2026-08-09)

- RFC 9106 (Argon2): https://www.rfc-editor.org/rfc/rfc9106 ·
  OWASP Password Storage: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
- Electron safeStorage (async; Linux basic_text): https://www.electronjs.org/docs/latest/api/safe-storage
- keytar ARQUIVADO (não usar): https://github.com/atom/node-keytar
- SQLCipher (raw key `PRAGMA key = x'...'`; design AES-256-CBC+HMAC): https://www.zetetic.net/sqlcipher/
- better-sqlite3-multiple-ciphers: https://github.com/m4heshd/better-sqlite3-multiple-ciphers
  (@journeyapps/sqlcipher sem Windows — descartado)
- expo-secure-store (~2 KB limit iOS; persiste pós-uninstall): https://docs.expo.dev/versions/latest/sdk/securestore/
- expo-sqlite useSQLCipher (dev build): https://docs.expo.dev/versions/latest/sdk/sqlite/
- react-native-quick-crypto (argon2 nativo JSI): https://github.com/margelo/react-native-quick-crypto ·
  noble-hashes (auditado, fallback JS): https://github.com/paulmillr/noble-hashes
- node:crypto argon2 (Node ≥ 24.7 → Electron ≥ 43): https://nodejs.org/api/crypto.html

## Host replication/failover (confirmado — ReplicationScout, 2026-08-09)

- etcd leases: https://etcd.io/docs/v3.5/tutorials/how-to-create-lease/ ·
  ZK leader election (sequence|ephemeral): https://zookeeper.apache.org/doc/current/recipes.html
- PostgreSQL warm standby (2-safe synchronous_commit): https://www.postgresql.org/docs/current/warm-standby.html
- SQLite backup API / VACUUM INTO: https://sqlite.org/backup.html · WAL: https://sqlite.org/wal.html
- Litestream (WAL shipping — avaliado e preterido): https://litestream.io/how-it-works/
- RFC 9420 §14 (Commits conflitantes — base do single-writer): https://www.rfc-editor.org/rfc/rfc9420.html
- FLP (consenso assíncrono impossível): https://groups.csail.mit.edu/tds/papers/Lynch/jacm85.pdf ·
  Brewer 2012 (partition mode): https://www.infoq.com/articles/cap-twelve-years-later-how-the-rules-have-changed/
- Tailscale control/data plane (modelo do rendezvous): https://tailscale.com/docs/concepts/control-data-planes

## Notas de consolidação

- mls-rs: sem auditoria externa publicada → planejar auditoria antes de V1; breaking changes
  pré-1.0 → pin + interop CI.
- react-native-webrtc New Arch: PR #1590 sem merge visível; iOS em validação → testar em device.
- raw key via expo-sqlite e rebuild ABI better-sqlite3 no Electron: [INFERENCE] → spike antes
  de congelar.
- WASM no Hermes (RN): experimental → usar UniFFI no mobile; spike antes de qualquer aposta wasm.
