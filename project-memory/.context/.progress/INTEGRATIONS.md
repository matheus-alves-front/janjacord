# INTEGRATIONS.md — JanjaCord

> Integrações externas materiais: purpose, data exposed, trust boundary, credentials, privacy
> impact, failure mode, fallback, self-host option. Fontes: research 2026-08-09 + docs oficiais.

## 1. OS keychain / secure storage (desktop + mobile)

- **Purpose:** guardar apenas valores pequenos — token opcional de unlock, credenciais de
  linking; NUNCA o vault inteiro (~2 KB limit iOS Keychain).
- **Data exposed:** tokens locais; nada sai do device.
- **Trust boundary:** proteção do SO por usuário; malware userspace pode descriptografar
  (documentado no threat model); Linux `basic_text` = sem proteção (detectar e avisar).
- **Credentials:** geridas pelo SO.
- **Privacy impact:** baixo (sem rede).
- **Failure mode:** invalidação por biometria (requireAuthentication) → fallback por senha;
  Android backup sem exclusão → dado ilegível (config plugin).
- **Self-host option:** n/a.
- **Stack:** Electron `safeStorage` (async, main); `expo-secure-store` (mobile).
- **Refs:** electronjs.org/api/safe-storage; docs.expo.dev/securestore

## 2. SQLite cifrado (SQLCipher)

- **Purpose:** vault file + estado efêmero/local no client e no host (server state, spool).
- **Data exposed:** arquivo cifrado (AES-256-CBC por página + HMAC-SHA512); raw key — nunca
  passphrase (KDF interno PBKDF2 fraco).
- **Trust boundary:** chave raw derivada/enrolada localmente (KEK Argon2id).
- **Credentials:** raw key 32 B (x'hex').
- **Privacy impact:** purge via secure_delete + VACUUM; WAL/journal cifrados.
- **Failure mode:** corrupção → recovery via recovery key; ABI rebuild no Electron
  ([INFERENCE] — spike); iOS WAL em background exige cipher_plaintext_header_size.
- **Self-host option:** n/a.
- **Stack:** `better-sqlite3-multiple-ciphers` (desktop); `expo-sqlite useSQLCipher` /
  `op-sqlite` (mobile, dev build).
- **Refs:** zetetic.net/sqlcipher; nodejs sqlite3 docs

## 3. MLS core (mls-rs)

- **Purpose:** E2EE de grupo (RFC 9420) — mensagens, membership changes, device keys.
- **Data exposed:** KeyPackages, credenciais (binding ID↔keys visível ao AS = JanjaNode),
  metadata de membership (quem entra/sai); sender data cifrado (DS não vê remetente).
- **Trust boundary:** DS (JanjaNode) fortemente consistente; não confiável para conteúdo.
- **Credentials:** signature key + HPKE keys por device; PSK opcional de recovery.
- **Privacy impact:** correlacionável quem envia/participa (RFC 9750 §8.2.4) — aceito
  (device-per-leaf).
- **Failure mode:** fork de Commits (prevenido por single-writer); membro forked → external
  commit; DS comprometido → DoS/delay, não leitura.
- **Self-host option:** sim (código open; auditoria externa a orçar antes de V1).
- **Stack:** mls-rs (Rust) — WASM (Electron) + UniFFI Kotlin/Swift (mobile); wrapper TS próprio
  (mls-rs-uniffi parado desde 2024).
- **Refs:** github.com/awslabs/mls-rs; RFC 9420/9750

## 4. WebRTC (nativo Chromium / react-native-webrtc / node-datachannel)

- **Purpose:** media (voz/vídeo) + DataChannel (mensagens P2P).
- **Data exposed:** media cifrada por DTLS par-a-par; metadata de transporte (endpoints);
  nada de conteúdo para o host (não participa de media na V1).
- **Trust boundary:** peers; TURN quando relay (vê metadata de transporte).
- **Credentials:** ICE candidates, TURN credentials (REST API curta duração).
- **Privacy impact:** direct mode expõe IP entre peers; relay-only esconde endereço direto.
- **Failure mode:** symmetric NAT sem TURN → falha; firewall UDP → TURN TCP/TLS (443);
  background mobile suspende fluxo (spool cobre).
- **Self-host option:** sim (clientes open).
- **Stack:** nativo Chromium (desktop); react-native-webrtc 124.x (mobile, New Arch RN 0.76+);
  node-datachannel (JanjaNode).
- **Refs:** RFC 8831/8827/8835; github.com/react-native-webrtc/react-native-webrtc

## 5. STUN/TURN (coturn)

- **Purpose:** conectividade NAT; relay para relay-only/symmetric NAT.
- **Data exposed:** allocations efêmeras; metadata de transporte (quem↔quem no relay);
  nunca conteúdo (E2EE).
- **Trust boundary:** operador do TURN (metadata, não conteúdo).
- **Credentials:** long-term credentials via TURN REST API (username=timestamp:user,
  password=base64(HMAC-SHA1(secret, username))), TTL curto.
- **Privacy impact:** relay-only concentra metadata no operador do relay (documentado).
- **Failure mode:** relay down → direct preferred degrada (fallback público explícito) ou
  relay-only falha seguro; denied-peer-ip evita SSRF via relay.
- **Self-host option:** sim (coturn; docker coturn/coturn; portas 3478/5349 + relay 49152-65535).
- **Refs:** RFC 8489/8656; github.com/coturn/coturn

## 6. Push (FCM + APNs)

- **Purpose:** notificação genérica opt-in "New activity on JanjaCord" — sem conteúdo.
- **Data exposed:** tokens de device (FCM/APNs) no push service central; payload 100% estático;
  tokens NUNCA expostos ao JanjaNode (capability tickets opacos).
- **Trust boundary:** Google/Apple veem token + horários de push (documentado); push service
  central retém o mínimo.
- **Credentials:** credenciais FCM v1 (OAuth service account) / APNs (token .p8 ES256) no
  push service.
- **Privacy impact:** correlação dispositivo↔horário possível para o operador do push service;
  sem conteúdo/sender/server/channel.
- **Failure mode:** entrega background não-garantida (iOS throttle 2–3/h; Android OEM/Doze);
  payload estático evita vazamento mesmo em erro de roteamento.
- **Self-host option:** push exige credenciais por-app — serviço central é inevitável
  (documentado no threat model); endpoints abstratos permitem implementação self-host do
  dispatcher, não das credenciais.
- **Refs:** firebase.google.com/docs/cloud-messaging; developer.apple.com usernotifications

## 7. Rendezvous (bootstrap/discovery)

- **Purpose:** hosts/peers se encontram por serverId; lease/arbitragem de failover.
- **Data exposed:** records assinados (serverId, endpoints efêmeros), TTL curto; sem contas.
- **Trust boundary:** operador do rendezvous (metadata mínima efêmera; nada durável).
- **Credentials:** assinatura da host key (serverId = fingerprint).
- **Privacy impact:** operador vê quais hosts anunciam/consultam (efêmero, rate-limited).
- **Failure mode:** rendezvous down → joins novos bloqueados, tráfego existente segue
  (Tailscale model); rate limits contêm abuso.
- **Self-host option:** sim (implementação open; DNS SRV/TXT bootstrap).
- **Refs:** libp2p rendezvous spec; RFC 2782/6763

## 8. Update distribution

- **Purpose:** atualizações desktop (self-host assinado) e mobile (lojas).
- **Data exposed:** versão do app, checksums; sem conteúdo.
- **Trust boundary:** update server (assinatura obrigatória; macOS code-sign).
- **Credentials:** signing keys (dev).
- **Privacy impact:** baixo (metadata mínima).
- **Failure mode:** update server down → app segue na versão atual; rollback por installer.
- **Self-host option:** sim — Hazel/Nuts/Nucleus/electron-release-server
  (update.electronjs.org exige repo GitHub público — inviável para app privado).
- **Refs:** electronjs.org/docs/latest/tutorial/updates

## 9. Stores / tooling de build

- **Purpose:** distribuição mobile (Play closed testing / TestFlight) e assinatura desktop.
- **Data exposed:** binários, metadados da loja.
- **Trust boundary:** Google/Apple (assinatura, revisão).
- **Privacy impact:** baixo; revisão da loja vê binário (não conteúdo de usuário).
- **Failure mode:** rejeição de review → ajustes; release lento → dev builds cobrem.
- **Self-host option:** parcial (sideload/ADB; não substitui lojas na prática V1).

## 10. Credenciais/secrets — política

- Secretos por componente: signing keys (update), TURN secret (coturn REST), push creds
  (FCM/APNs), ML-KEM/etc. — gerenciados por deploy (env/secret manager), nunca no cliente.
- No client: apenas chaves locais (vault) e credenciais efêmeras (TURN timestamp+HMAC).
